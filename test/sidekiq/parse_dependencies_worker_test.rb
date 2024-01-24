require "test_helper"

class ParseSbomWorkerTest < ActiveSupport::TestCase
  test 'perform' do
    @job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')
    @job.expects(:perform_sbom_parsing).returns(true)
    Job.expects(:find_by_id!).with(@job.id).returns(@job)
    job = ParseSbomWorker.new
    job.perform(@job.id)
  end
end