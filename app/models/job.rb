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
