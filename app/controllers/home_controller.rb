class HomeController < ApplicationController
  def index
    @sbom_formats = Job.sbom_formats
  end
end