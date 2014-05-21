require 'oauth2'

module RubyBox  
  class Session

    OAUTH2_URLS = {
      :site => 'https://www.box.com',
      :authorize_url => "/api/oauth2/authorize",
      :token_url => "/api/oauth2/token"
    }
    
    def initialize(opts={}, backoff=0.1)

      @backoff = backoff # try not to excessively hammer API.

      if opts[:client_id]
        @oauth2_client = OAuth2::Client.new(opts[:client_id], opts[:client_secret], OAUTH2_URLS.dup)
        @access_token = OAuth2::AccessToken.new(@oauth2_client, opts[:access_token]) if opts[:access_token]
        @refresh_token = opts[:refresh_token]
        @as_user = opts[:as_user]
        @behalf_of = opts[:behalf_of]
        @refresh_callback = opts[:refresh_callback]
        @refresh_lock = opts[:refresh_lock]
        @get_tokens = opts[:get_tokens]
      else # Support legacy API for historical reasons.
        @api_key = opts[:api_key]
        @auth_token = opts[:auth_token]
      end

      if opts[:log_path]
        @service_email = opts[:service_email]
        @log = Logger.new(opts[:log_path], 'daily')
        @log.formatter = -> severity, datetime, progname, msg { "#{ severity } #{ datetime.strftime("%Y-%m-%d %H:%M:%S.%6N %z") } RubyBox::Session #{@service_email} #{msg}\n" }
      end
    end

    def authorize_url(redirect_uri)
      @redirect_uri = redirect_uri
      @oauth2_client.auth_code.authorize_url(:redirect_uri => redirect_uri)
    end

    def get_access_token(code)
      @access_token = @oauth2_client.auth_code.get_token(code)
    end

    def refresh_token(refresh_token, lock=nil)
      refresh_access_token_obj = OAuth2::AccessToken.new(@oauth2_client, @access_token.token, {'refresh_token' => refresh_token})
      @access_token = refresh_access_token_obj.refresh!

      new_refresh_token = @access_token.refresh_token 
      @refresh_token = new_refresh_token if @refresh_token
      @log.debug("Refresh token request returned access token #{ @access_token.token } and refresh token #{ new_refresh_token } for lock #{ lock }") if @log
      @refresh_callback.call(@access_token.token, new_refresh_token, lock) if !@refresh_callback.nil? && @refresh_callback.lambda?

      @access_token
    end

    def refresh_token_with_lock(refresh)
      @log.debug("Request refresh token lock") if @log
      lock = @refresh_lock.call
      if !lock.nil?
        @log.debug("Received refresh token lock #{ lock }, making oauth request") if @log
        refresh_token(refresh, lock)
      elsif !@get_tokens.nil? && @get_tokens.lambda?
        @log.debug("Failed to get refresh token lock, trying to reload from database") if @log
        refresh, access = @get_tokens.call
        @access_token = OAuth2::AccessToken.new(@oauth2_client, access) if @access_token
        @refresh_token = refresh if @refresh_token
      end
    end

    def build_auth_header
      "BoxAuth api_key=#{@api_key}&auth_token=#{@auth_token}"
    end

    def get(url, raw=false)
      uri = URI.parse(url)
      request = Net::HTTP::Get.new( uri.request_uri )
      resp = request( uri, request, raw )
    end

    def delete(url, raw=false)
      uri = URI.parse(url)
      request = Net::HTTP::Delete.new( uri.request_uri )
      resp = request( uri, request, raw )
    end
    
    def request(uri, request, raw=false, retries=true)

      response = request_retry(uri, request, raw, retries)

      if response.is_a? Net::HTTPNotFound
        raise RubyBox::ObjectNotFound
      end

      sleep(@backoff) # try not to excessively hammer API.

      handle_errors( response, raw )
    end

    def request_retry(uri, request, raw, retries)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.ssl_version = :SSLv3
      #http.set_debug_output($stdout)

      if @access_token
        request['Authorization'] = "Bearer #{@access_token.token}"
      else
        request.add_field('Authorization', build_auth_header)
      end

      request['As-User'] = @as_user if @as_user
      request['On-Behalf-Of'] = @behalf_of if @behalf_of

      response = http.request(request)

      # Got unauthorized (401) status, try to refresh the token
      if response.code.to_i == 401 and @refresh_token and retries
        if !@refresh_lock.nil? && @refresh_lock.lambda?
          refresh_token_with_lock(@refresh_token)
        else
          refresh_token(@refresh_token)
        end

        sleep(@backoff) # try not to excessively hammer API.

        request_retry(uri, request, raw, false)
      else
        response
      end
    end

    def do_stream(url, opts)
      params = {
        :content_length_proc => opts[:content_length_proc],
        :progress_proc => opts[:progress_proc]        
      }

      if @access_token
        params['Authorization'] = "Bearer #{@access_token.token}"
      else
        params['Authorization'] = build_auth_header
      end

      params['As-User'] = @as_user if @as_user
      params['On-Behalf-Of'] = @behalf_of if @behalf_of

      open(url, params)
    end
    
    def handle_errors( response, raw )
      status = response.code.to_i
      body = response.body
      begin
        parsed_body = JSON.parse(body)
      rescue
        msg = body.nil? || body.empty? ? "no data returned" : body
        parsed_body = { "message" =>  msg }
      end

      # status is used to determine whether
      # we need to refresh the access token.
      parsed_body["status"] = status

      case status / 100
      when 3
        # 302 Found. We should return the url
        parsed_body["location"] = response["Location"] if status == 302                  
      when 4
        raise(RubyBox::ItemNameInUse.new(parsed_body, status, body), parsed_body["message"]) if parsed_body["code"] == "item_name_in_use"
        raise(RubyBox::AuthError.new(parsed_body, status, body), parsed_body["message"]) if parsed_body["code"] == "unauthorized" || status == 401
        raise(RubyBox::RequestError.new(parsed_body, status, body), parsed_body["message"])
      when 5
        raise(RubyBox::ServerError.new(parsed_body, status, body), parsed_body["message"])
      end
      raw ? body : parsed_body
    end
  end
end
