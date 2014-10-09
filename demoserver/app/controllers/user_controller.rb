class UserController < ApplicationController
  def new
    session[:username] = 'this is a test cookie'
  end

  def index
    cookie = session[:username]
    render json: cookie
  end
end
