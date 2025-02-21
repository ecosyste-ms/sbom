module ApplicationHelper
  def meta_title
    [@meta_title, 'Ecosyste.ms: SBOM'].compact.join(' | ')
  end

  def meta_description
    @meta_description || app_description
  end

  def app_name
    "SBOM"
  end

  def app_description
    'An open API service to parse and convert between SBOM file formats.'
  end
end
