class Job < ApplicationRecord
  class DownloadError < StandardError; end

  DOWNLOAD_TIMEOUT = 30
  MAX_DOWNLOAD_SIZE = 50.megabytes
  MAX_REDIRECTS = 5
  REDIRECT_CODES = [301, 302, 303, 307, 308]
  DENIED_RANGES = %w[
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
    192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4
    ::/128 ::1/128 64:ff9b::/96 fc00::/7 fe80::/10 ff00::/8
  ].map { |range| IPAddr.new(range) }
  FILE_EXTENSIONS = Sbom::Parser::EXTENSION_MAP.keys + %w[.json .xml]

  validates_presence_of :url
  validates_uniqueness_of :id

  scope :status, ->(status) { where(status: status) }

  def self.check_statuses
    Job.where(status: ["queued", "working"]).find_each(&:check_status)
  end

  def check_status
    return if sidekiq_id.blank?
    return if finished?
    update(status: fetch_status)
  end

  def fetch_status
    Sidekiq::Status.status(sidekiq_id).presence || 'error'
  end

  def finished?
    ['complete', 'error'].include?(status)
  end

  def parse
    Dir.mktmpdir do |dir|
      sha256 = download_file(dir)
      results = parse_sbom(dir)
      update!(results: results, status: 'complete', sha256: sha256)
    end
  rescue => e
    update(results: {error: e.inspect}, status: 'error')
  end

  def parse_sbom(dir)
    path = working_directory(dir)
    sbom = Sbom.parse_file(path)
    sbom.to_h
  end

  def download_file(dir)
    path = working_directory(dir)
    target = url
    response = nil
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DOWNLOAD_TIMEOUT

    (MAX_REDIRECTS + 1).times do
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise DownloadError, "download timed out" if remaining <= 0
      response = fetch(target, path, timeout: remaining)
      raise DownloadError, "download timed out" if response.timed_out?
      break unless REDIRECT_CODES.include?(response.code)
      location = response.headers && response.headers["Location"]
      raise DownloadError, "redirect without a location" if location.blank?
      target = URI.join(target, Array(location).last).to_s
    end

    raise DownloadError, "too many redirects" if REDIRECT_CODES.include?(response.code)
    raise DownloadError, "unexpected response #{response.code}" unless response.code == 200

    Digest::SHA256.file(path).hexdigest
  end

  # Redirects are followed by the caller so every hop gets the same checks.
  def fetch(target, path, timeout:)
    uri = URI.parse(target)
    raise DownloadError, "unsupported url" unless uri.is_a?(URI::HTTP) && uri.hostname.present?

    options = { followlocation: false, timeout_ms: (timeout * 1000).ceil }
    pinned = public_addresses(uri.hostname)
    # pin the checked addresses so curl cannot re-resolve to a different one
    resolve_list = Ethon::Curl.slist_append(nil, "#{uri.hostname}:#{uri.port}:#{pinned.join(',')}") if pinned
    options[:resolve] = resolve_list if resolve_list

    size = 0
    response = File.open(path, "wb") do |file|
      request = Typhoeus::Request.new(uri.to_s, options)
      request.on_body do |chunk, streamed|
        next unless streamed.code == 200
        size += chunk.bytesize
        next :abort if size > MAX_DOWNLOAD_SIZE
        file.write(chunk)
      end
      request.run
    end

    raise DownloadError, "download larger than #{MAX_DOWNLOAD_SIZE} bytes" if size > MAX_DOWNLOAD_SIZE
    response
  ensure
    Ethon::Curl.slist_free_all(resolve_list) if resolve_list
  end

  # Returns the addresses to pin for a hostname, nil for an IP literal.
  def public_addresses(host)
    literal = begin
      IPAddr.new(host)
    rescue IPAddr::InvalidAddressError
      nil
    end

    addresses = literal ? [literal.to_s] : resolve_host(host)
    raise DownloadError, "could not resolve #{host}" if addresses.empty?
    raise DownloadError, "address not allowed" if addresses.any? { |address| denied_address?(address) }

    return nil if literal
    addresses.map { |address| address.include?(":") ? "[#{address}]" : address }
  end

  def resolve_host(host)
    Addrinfo.getaddrinfo(host, nil, nil, :STREAM).map(&:ip_address).uniq
  end

  def denied_address?(address)
    ip = IPAddr.new(address.split("%").first)
    ip = ip.native if ip.ipv4_mapped?
    DENIED_RANGES.any? { |range| range.include?(ip) }
  end

  # The URL basename is attacker-controlled, so only a known extension is
  # kept; Sbom.parse_file picks the format from it.
  def working_directory(dir)
    File.join([dir, "download#{FILE_EXTENSIONS.find { |extension| url.end_with?(extension) }}"])
  end

  def self.sbom_formats
    [
      'cyclonedx-json',
      'cyclonedx-xml',
      'spdx-json',
      'spdx-xml',
      'spdx-yaml',
      'spdx-rdf',
      'spdx-tag-value'
    ]
  end

  def self.sbom_version
    Sbom::VERSION
  end
end
