class Job < ApplicationRecord
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

  def parse_sbom_async
    sidekiq_id = ParseSbomWorker.perform_async(id)
    update(sidekiq_id: sidekiq_id)
  end

  def perform_license_parsing
    begin
      Dir.mktmpdir do |dir|
        sha256 = download_file(dir)
        results = parse_sbom(dir)
        update!(results: results, status: 'complete', sha256: sha256)
      end
    rescue => e
      update(results: {error: e.inspect}, status: 'error')
    end
  end

  def parse_sbom(dir)
    path = working_directory(dir)

    case mime_type(path)
    when "application/zip", "application/java-archive"
      destination = File.join([dir, 'zip'])
      `mkdir #{destination} && bsdtar --strip-components=1 -xvf #{path} -C #{destination} > /dev/null 2>&1 `
      results = syft_convert(destination)
    when "application/gzip"
      destination = File.join([dir, 'tar'])
      `mkdir #{destination} && tar xzf #{path} -C #{destination} --strip-components 1`
      results = syft_convert(destination)
    else
      results = []
    end

    return results
  end

  def syft_convert(path, format = 'syft-json')
    # do the thing
  end

  def download_file(dir)
    path = working_directory(dir)
    downloaded_file = File.open(path, "wb")

    request = Typhoeus::Request.new(url, followlocation: true)
    request.on_headers do |response|
      return nil unless [200,301,302].include? response.code
    end
    request.on_body { |chunk| downloaded_file.write(chunk) }
    request.on_complete { downloaded_file.close }
    request.run

    return Digest::SHA256.hexdigest File.read(path)
  end

  def mime_type(path)
    IO.popen(
      ["file", "--brief", "--mime-type", path],
      in: :close, err: :close
    ) { |io| io.read.chomp }
  end

  def working_directory(dir)
    File.join([dir, basename])
  end

  def basename
    File.basename(url)
  end

  def self.sbom_formats
    [
      'cyclonedx-json',
      'cyclonedx-xml',
      'github-json',
      'spdx-json',
      'spdx-tag-value',
      'syft-json',
      'syft-table',
      'syft-text'
    ]
  end
end
