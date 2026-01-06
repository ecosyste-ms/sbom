require "test_helper"

class JobTest < ActiveSupport::TestCase
  context 'validations' do
    should validate_presence_of(:url)
    should validate_uniqueness_of(:id).case_insensitive
  end

  setup do
    @job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip', sidekiq_id: '123', ip: '123.456.78.9')
  end

  test 'check_status' do
    Sidekiq::Status.expects(:status).with(@job.sidekiq_id).returns(:queued)
    @job.check_status
    assert_equal @job.status, "queued"
  end

  test 'parse' do
    stub_request(:get, @job.url).to_return(status: 200, body: '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}')
    @job.parse
    assert_equal 'complete', @job.status
  end

  test 'parse_sbom' do
    skip "This test is not working yet"
    Dir.mktmpdir do |dir|
      FileUtils.cp(File.join(file_fixture_path, 'main.zip'), dir)
      results = @job.parse_sbom(dir)
      assert_equal results[:sbom].length, 1
      assert_equal results[:matched_files].length, 1
      assert_equal results[:sbom].first[:name], "GNU Affero General Public License v3.0"
      assert_equal results[:matched_files].first[:filename], "LICENSE"
    end
  end

  test 'download_file' do
    stub_request(:get, "https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip")
      .to_return({ status: 200, body: file_fixture('main.zip') })

    Dir.mktmpdir do |dir|
      sha256 = @job.download_file(dir)
      assert_equal sha256, '546b13eb945186f67d2480910dce773ca0e2539b80cadafe7bb2fe3c537800ec'
    end
  end
end
