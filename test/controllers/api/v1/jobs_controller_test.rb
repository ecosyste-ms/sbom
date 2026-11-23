require 'test_helper'

class ApiV1JobsControllerTest < ActionDispatch::IntegrationTest
  test 'submit a job' do
    Job.any_instance.stubs(:parse)
    post api_v1_jobs_path(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')
    assert_response :redirect
    assert_match /\/api\/v1\/jobs\//, @response.location
  end

  CYCLONEDX = '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"left-pad","version":"1.0.0"}]}'

  test 'downloads and parses an sbom' do
    stub_request(:get, 'https://example.com/bom.cdx.json').to_return(status: 200, body: CYCLONEDX)
    job = submit('https://example.com/bom.cdx.json')

    assert_equal 'complete', job.status
    assert_equal 'cyclonedx', job.results['type']
    assert_equal Digest::SHA256.hexdigest(CYCLONEDX), job.sha256
  end

  test 'picks the format from the url extension' do
    body = "spdxVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nname: example\npackages:\n- name: left-pad\n  SPDXID: SPDXRef-Package\n  versionInfo: 1.0.0\n"
    stub_request(:get, 'https://example.com/bom.spdx.yaml').to_return(status: 200, body: body)
    job = submit('https://example.com/bom.spdx.yaml')

    assert_equal 'complete', job.status
    assert_equal 'spdx', job.results['type']
  end

  test 'refuses loopback, private and metadata addresses' do
    %w[http://127.0.0.1/bom.json http://10.0.0.5/bom.json http://169.254.169.254/latest http://[::1]/bom.json http://[::ffff:127.0.0.1]/bom.json].each do |url|
      job = submit(url)
      assert_equal 'error', job.status, url
      assert_match 'address not allowed', job.results['error'], url
    end
    assert_not_requested :get, /.*/
  end

  test 'refuses hostnames that resolve to a private address' do
    Job.any_instance.stubs(:resolve_host).returns(['93.184.216.34', '192.168.1.1'])
    job = submit('https://example.com/bom.json')

    assert_equal 'error', job.status
    assert_match 'address not allowed', job.results['error']
    assert_not_requested :get, /.*/
  end

  test 'refuses non-http urls' do
    %w[file:///etc/passwd gopher://example.com/_x ftp://example.com/bom.json].each do |url|
      job = submit(url)
      assert_equal 'error', job.status, url
      assert_match 'unsupported url', job.results['error'], url
    end
  end

  test 'refuses a redirect to a private address or a non-http url' do
    { 'http://169.254.169.254/latest/meta-data' => 'address not allowed', 'file:///etc/passwd' => 'unsupported url' }.each do |location, error|
      stub_request(:get, 'https://example.com/bom.json').to_return(status: 302, headers: { 'Location' => location })
      job = submit('https://example.com/bom.json')

      assert_equal 'error', job.status, location
      assert_match error, job.results['error'], location
    end
    assert_not_requested :get, /169\.254/
  end

  test 'follows a redirect to a public address' do
    stub_request(:get, 'https://example.com/bom.json').to_return(status: 302, headers: { 'Location' => '/mirror/bom.json' })
    stub_request(:get, 'https://example.com/mirror/bom.json').to_return(status: 200, body: CYCLONEDX)
    job = submit('https://example.com/bom.json')

    assert_equal 'complete', job.status
    assert_equal Digest::SHA256.hexdigest(CYCLONEDX), job.sha256
  end

  test 'stops after too many redirects' do
    stub_request(:get, 'https://example.com/bom.json').to_return(status: 302, headers: { 'Location' => 'https://example.com/bom.json' })
    job = submit('https://example.com/bom.json')

    assert_equal 'error', job.status
    assert_match 'too many redirects', job.results['error']
    assert_requested :get, 'https://example.com/bom.json', times: Job::MAX_REDIRECTS + 1
  end

  test 'refuses downloads over the size limit' do
    stub_request(:get, 'https://example.com/bom.json').to_return(status: 200, body: 'a' * 2048)
    job = with_limit(:MAX_DOWNLOAD_SIZE, 1024) { submit('https://example.com/bom.json') }

    assert_equal 'error', job.status
    assert_match 'download larger than', job.results['error']
  end

  test 'marks failed and timed out downloads as errors' do
    stub_request(:get, 'https://example.com/missing.json').to_return(status: 404, body: CYCLONEDX)
    stub_request(:get, 'https://example.com/slow.json').to_timeout

    { 'https://example.com/missing.json' => 'unexpected response 404', 'https://example.com/slow.json' => 'timed out' }.each do |url, error|
      job = submit(url)
      assert_equal 'error', job.status, url
      assert_match error, job.results['error'], url
      assert_nil job.sha256, url
    end
  end

  test 'url filenames do not reach the filesystem' do
    ['https://example.com/a/..', "https://example.com/#{'a' * 300}.json"].each do |url|
      stub_request(:get, url).to_return(status: 200, body: CYCLONEDX)
      job = submit(url)
      assert_equal 'complete', job.status, url
    end
  end

  def submit(url)
    post api_v1_jobs_path, params: { url: url }
    assert_response :redirect
    Job.order(:created_at).last
  end

  def with_limit(name, bytes)
    original = Job.const_get(name)
    Job.send(:remove_const, name)
    Job.const_set(name, bytes)
    yield
  ensure
    Job.send(:remove_const, name)
    Job.const_set(name, original)
  end

  test 'submit an invalid job' do
    post api_v1_jobs_path
    assert_response :bad_request

    actual_response = JSON.parse(@response.body)

    assert_equal actual_response["title"], "Bad Request"
    assert_equal actual_response["details"], ["Url can't be blank"]
  end

  test 'check on a job' do
    @job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')

    @job.expects(:check_status)
    Job.expects(:find).with(@job.id).returns(@job)

    get api_v1_job_path(id: @job.id)
    assert_response :success
    assert_template 'jobs/show', file: 'jobs/show.json.jbuilder'
    
    actual_response = JSON.parse(@response.body)

    assert_equal actual_response["url"], @job.url
  end
end