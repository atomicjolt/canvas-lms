class PtLoginController < ApplicationController
  include Login::Shared

  def login
  # reset_session_for_login
    @user = User.find params[:user_id]
    pseudonym = Pseudonym.find_by(user_id: params[:user_id])
    @domain_root_account.pseudonym_sessions.create!(pseudonym, false)
    session[:is_proctored] = true
    redirect_to "/courses/#{params[:course_id]}/quizzes/#{params[:quiz_id]}/take?borderless=true"
  end

end
