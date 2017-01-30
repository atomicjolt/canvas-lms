module Concerns::ProctorQuizzes
  extend ActiveSupport::Concern

    included do
      layout :choose_layout
    end

private

  def choose_layout
    session[:is_proctored] ? "borderless_lti" : "application"
  end
end
