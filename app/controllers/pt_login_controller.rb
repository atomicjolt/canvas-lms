class PtLoginController < ApplicationController
  include Login::Shared
  def login
    reset_session_for_login
    user = User.find params[:user_id]
    pseudonym = Pseudonym.find_by(user_id: params[:user_id])
    @domain_root_account.pseudonym_sessions.create!(pseudonym, false)
    custom_successful_login(user, pseudonym)
    # redirect_to :root
  end

private
  def custom_successful_login(user, pseudonym, otp_passed = false)
    CanvasBreachMitigation::MaskingSecrets.reset_authenticity_token!(cookies)
    Auditors::Authentication.record(pseudonym, 'login')

    # Since the user just logged in, we'll reset the context to include their info.
    setup_live_events_context
    # TODO: Only send this if the current_pseudonym's root account matches the current root
    # account?
    Canvas::LiveEvents.logged_in(session)

    otp_passed ||= user.validate_otp_secret_key_remember_me_cookie(cookies['canvas_otp_remember_me'], request.remote_ip)
    unless otp_passed
      mfa_settings = user.mfa_settings(pseudonym_hint: @current_pseudonym)
      if (user.otp_secret_key && mfa_settings == :optional) ||
          mfa_settings == :required
        session[:pending_otp] = true
        return redirect_to otp_login_url
      end
    end

    if pseudonym.account_id != (@real_domain_root_account || @domain_root_account).id
      flash[:notice] = t("You are logged in at %{institution1} using your credentials from %{institution2}",
                         institution1: (@real_domain_root_account || @domain_root_account).name,
                         institution2: pseudonym.account.name)
    end

    if pseudonym.account_id == Account.site_admin.id && Account.site_admin.delegated_authentication?
      cookies['canvas_sa_delegated'] = {
          :value => '1',
          :domain => remember_me_cookie_domain,
          :httponly => true,
          :secure => CanvasRails::Application.config.session_options[:secure]
      }
    end
    session[:require_terms] = true if @domain_root_account.require_acceptance_of_terms?(user)

    redirect_to :root
  end
end
