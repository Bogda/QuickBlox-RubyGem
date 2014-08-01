require 'net/http'
require 'json'
require 'rest_client'
require 'yaml'
require "uri"
require "net/http/post/multipart"
require 'base64'


class Quickblox

  def configs
    config = YAML.load_file("#{Rails.root}/config/quickblox.yml")[Rails.env].with_indifferent_access
    @application_id = config["default"]["application_id"]
    @auth_key = config["default"]["auth_key"]
    @auth_secret = config["default"]["auth_secret"]
    @user_owner_id = config["default"]["user_owner_id"]
    @server=config["default"]["server"]
    #to remove - for debug
    @user_login=config["default"]["user_login"]
    @user_password=config["default"]["user_password"]
    @device_platform= config["default"]["device_platform"]
    @device_udid= config["default"]["device_udid"]

  end


  def initialize
    configs
    @auth_uri=URI("http://"+@server.to_s+'/auth.json')
    @users_uri=URI("http://"+@server.to_s+'/users')
    @geodata_uri=URI("http://"+@server.to_s+'/geodata')
    @places_uri=URI("http://"+@server.to_s+'/places')
    @files_uri=URI("http://"+@server.to_s+'/blobs')
    @pushtokens_uri=URI("http://"+@server.to_s+'/push_tokens')
    @gamemodes_uri=URI("http://"+@server.to_s+'/gamemodes')
    @token=nil
    @token_type=nil
    @users_count = nil
    @user_id = nil

  end

  def user_login=(value)
    @user_login=value
  end

  def user_login
    @user_login
  end

  def user_password=(value)
    @user_password=value
  end

  def user_password
    @user_password
  end

  def device_platform=(value)
    @device_platform=value
  end

  def device_udid
    @device_udid
  end

  def get_user_id
    @token = get_token("user") unless @token_type=='user'
    @user_id
  end

  def get_token(type = 'app')
    destroy_token if @token
    timestamp=Time.now.to_i
    nonce=rand(10000)
    hash = {:application_id => @application_id, :nonce => nonce, :auth_key => @auth_key, :timestamp => timestamp}
    hash.merge!({:user => {:login => @user_login, :password => @user_password, :owner_id => @user_owner_id}}) if type == 'user' || type == 'user_device'
    hash.merge!({:device => {:platform => @device_platform, :udid => @device_udid}}) if type == 'device' || type == 'user_device'
    normalized= normalize(hash)
    digest = OpenSSL::Digest.new('sha1')
    signature = OpenSSL::HMAC.hexdigest(digest, @auth_secret, normalized)
    req = Net::HTTP::Post.new(@auth_uri.path)
    req.body = "#{normalized}&signature=#{signature}"
    response = Net::HTTP.start(@auth_uri.host, @auth_uri.port) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    @token_type=type
    @user_id=JSON.parse(response.body)["session"]["user_id"]
    @token=JSON.parse(response.body)["session"]["token"]
  end

  def destroy_token
    http = Net::HTTP.new(@server)
    delete_token = Net::HTTP::Delete.new("/auth_exit?token=#{@token}")
    @token=nil
    response=http.request(delete_token)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end


  def get_users_count(at_uri=nil, at_param=nil)
    @token = get_token unless @token
    response = Net::HTTP.get_response(URI(@users_uri.to_s+"#{at_uri}.json")+"?token=#{@token}#{at_param}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)["total_entries"]
  end

  def get_all_users_list
    @token = get_token unless @token
    @users_count = get_users_count unless @users_count
    requests=(@users_count/100).to_i+1
    users=[]
    i=1
    while i <= requests do
      user_list=Net::HTTP.get_response(URI(@users_uri.to_s+".json")+"?token=#{@token}&per_page=100&page=#{i}")
      i+=1
      users.concat JSON.parse(user_list.body)["items"]
    end
    users
  end

  def get_users_list (page=1, per_page=10)
    @token = get_token unless @token
    response=Net::HTTP.get_response(URI(@users_uri.to_s+".json")+"?token=#{@token}&per_page=#{per_page}&page=#{page}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def signup_user(user_params)
    @token = get_token unless @token_type=='app'
    user_params.merge! "token" => @token, "user[owner_id]" => @user_owner_id
    normalized= normalize(user_params)
    req = Net::HTTP::Post.new(URI(@users_uri.to_s+".json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@users_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_user_by_id(id)
    @token = get_token unless @token
    response = Net::HTTP.get_response(URI(@users_uri.to_s+"/#{id}.json")+"?token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_user_by_login(login)
    @token = get_token unless @token
    response = Net::HTTP.get_response(URI(@users_uri.to_s+"/by_login.json")+"?token=#{@token}&login=#{login}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_all_users_by_fullname(fullname)
    en_fullname = URI::encode(fullname)
    @token = get_token unless @token
    get_fullname_count= get_users_count("/by_full_name", "&full_name=#{en_fullname}")
    requests=(get_fullname_count/100).to_i+1
    users=[]
    i=1
    while i <= requests do
      user_list=Net::HTTP.get_response(URI(@users_uri.to_s+"/by_full_name.json")+"?token=#{@token}&per_page=100&page=#{i}&full_name=#{en_fullname}")
      i+=1
      users.concat JSON.parse(user_list.body)["items"]
    end
    users
  end

  def get_users_by_fullname(fullname, page=1, per_page=10)
    en_fullname = URI::encode(fullname)
    @token = get_token unless @token
    response=Net::HTTP.get_response(URI(@users_uri.to_s+"/by_full_name.json")+"?token=#{@token}&per_page=#{per_page}&page=#{page}&full_name=#{en_fullname}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_user_by_facebook_id(fbid)
    @token = get_token unless @token
    response= Net::HTTP.get_response(URI(@users_uri.to_s+"/by_facebook_id.json")+"?token=#{@token}&facebook_id=#{fbid}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_user_by_twitter_id(twid)
    @token = get_token unless @token
    response= Net::HTTP.get_response(URI(@users_uri.to_s+"/by_twitter_id.json")+"?token=#{@token}&twitter_id=#{twid}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_user_by_email(email)
    @token = get_token unless @token
    response= Net::HTTP.get_response(URI(@users_uri.to_s+"/by_email.json")+"?token=#{@token}&email=#{email}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_all_users_by_tags(tags)
    en_tags = URI::encode(tags)
    @token = get_token unless @token
    get_tags_count= get_users_count("/by_tags", "&tags=#{en_tags}")
    requests=(get_tags_count/100).to_i+1
    users=[]
    i=1
    while i <= requests do
      user_list=Net::HTTP.get_response(URI(@users_uri.to_s+"/by_tags.json")+"?token=#{@token}&per_page=100&page=#{i}&tags=#{en_tags}")
      i+=1
      users.concat JSON.parse(user_list.body)["items"]
    end
    users
  end

  def get_users_by_tags(tags, page=nil, per_page=nil)
    en_tags = URI::encode(tags)
    @token = get_token unless @token
    page=1 unless page
    per_page=10 unless per_page
    response=Net::HTTP.get_response(URI(@users_uri.to_s+"/by_tags.json")+"?token=#{@token}&per_page=#{per_page}&page=#{page}&tags=#{en_tags}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def update_user(user_params)
    @token = get_token("user") unless @token_type=='user'
    user_params.merge! "token" => @token
    normalized= normalize(user_params)
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI(@users_uri.to_s+"/"+@user_id.to_s+".json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@users_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_user
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete_user = Net::HTTP::Delete.new("/users/#{@user_id}?token=#{@token}")
    response=http.request(delete_user)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def get_user_by_external_id (external_id)
    @token = get_token unless @token
    response= Net::HTTP.get_response(URI(@users_uri.to_s+"/external/#{external_id}.json")+"?token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  #Get external ID by user ID
  def get_external_id_by_user_id(id)
    get_user_by_id(id)["external_user_id"]
  end


  def create_geodatum(geodata_params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    geodata_params.merge! "token" => @token
    normalized= normalize(geodata_params)
    req = Net::HTTP::Post.new(URI(@geodata_uri.to_s+".json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@geodata_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_geodata_by_id (geodata_id)
    @token = get_token unless @token
    response= Net::HTTP.get_response(URI(@geodata_uri.to_s+"/#{geodata_id}.json")+"?token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_geodata(params)
    @token = get_token unless @token
    normalized= normalize(params)
    response= Net::HTTP.get_response(URI(@geodata_uri.to_s+"/find.json")+"?#{normalized}&token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_geodata(days)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete_geodata = Net::HTTP::Delete.new("/geodata?token=#{@token}&days=#{days}")
    response=http.request(delete_geodata)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def delete_geodata_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete_geodata = Net::HTTP::Delete.new("/geodata/#{id}?token=#{@token}")
    response=http.request(delete_geodata)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_place(place_params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    place_params.merge! "token" => @token
    normalized= normalize(place_params)
    req = Net::HTTP::Post.new(URI(@places_uri.to_s+".json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@places_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def get_places(page=1, per_page=10)
    @token = get_token unless @token
    response=Net::HTTP.get_response(URI(@places_uri.to_s+".json")+"?token=#{@token}&per_page=#{per_page}&page=#{page}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_places_by_id(id)
    @token = get_token unless @token
    response=Net::HTTP.get_response(URI(@places_uri.to_s+"/#{id}.json")+"?token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def update_place_by_id(id, place_params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    place_params.merge! "token" => @token
    normalized= normalize(place_params)
    req = Net::HTTP::Put.new(URI(@places_uri.to_s+"/#{id}.json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@places_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_place_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete_place = Net::HTTP::Delete.new("/places/#{id}?token=#{@token}")
    response=http.request(delete_place)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end


  #Content API Requests


  def create_file(filename, file_params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    file_params.merge! "token" => @token, "blob[multipart]" => 0
    normalized = normalize(file_params)
    req = Net::HTTP::Post.new(URI(@files_uri.to_s+".json").path)
    req.body = "#{normalized}"
    response = Net::HTTP.start(URI(@files_uri.to_s+".json").host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    link=JSON.parse(response.body)["blob"]["blob_object_access"]["params"]
    uri=URI(link)
    query = {}
    CGI.parse(uri.query).map { |k, v| query.merge!({k => v[0]}) }
    query.merge! "file" => File.read(filename)
    req = Net::HTTP::Post::Multipart.new uri.path, query
    s3=Net::HTTP.start(uri.host, uri.port) do |http|
      http.request(req)
    end
    return {:response_code => s3.code, :response_header => s3, :response_body => (JSON.parse(s3.body) rescue nil)} unless s3.code == "201"
    blobid = JSON.parse(response.body)["blob"]["id"]
    filesize = File.size(filename)
    req = Net::HTTP::Put.new(URI(@files_uri.to_s+"/#{blobid}/complete.json").path)
    req.body = "blob[size]=#{filesize}&token=#{@token}"
    complete=Net::HTTP.start(@places_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => complete.code, :response_header => complete, :response_body => (JSON.parse(complete.body) rescue nil)} unless complete.code == "200"
    get_file_info_by_id(blobid)
  end

  def get_file_info_by_id(id)
    @token = get_token unless @token
    response = Net::HTTP.get_response(URI(@files_uri.to_s+"/#{id}.json")+"?token=#{@token}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_files_list(page=1, per_page=10)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI(@files_uri.to_s+".json")+"?token=#{@token}&page=#{page}&per_page=#{per_page}")
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_file_link_by_uid(uid)
    @token = get_token unless @token
    response = Net::HTTP.get_response(URI(@files_uri.to_s+"/#{uid}.json"+"?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "302"
    CGI::unescapeHTML(response.body.gsub("<html><body>You are being <a href=\"", '').gsub("\">redirected</a>.</body></html>", ''))
  end

  def get_file_link_by_id(id)
    @token = get_token unless @token
    req = Net::HTTP::Post.new(URI(@files_uri.to_s+"/#{id}/getblobobjectbyid.json").path)
    req.body = "token=#{@token}"
    response=Net::HTTP.start(@files_uri.host) do |http|
      http.request(req)
    end
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)["blob_object_access"]["params"]
  end

  def edit_file_by_id(id, params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI(@files_uri.to_s+"/#{id}.json").path)
    params.merge! "token" => @token
    normalized= normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@files_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_file(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete=Net::HTTP::Delete.new("/blobs/#{id}/?token=#{@token}")
    response=http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def increase_file_links(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI(@files_uri.to_s+"/#{id}/retain.json").path)
    req.body = "token=#{@token}"
    response=Net::HTTP.start(@files_uri.host) do |http|
      http.request(req)
    end
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}

  end


  #Messages API request

  def create_push_token(params)
    @token = get_token("user_device") unless @token_type=='user_device'
    params.merge! "token" => @token
    normalized= normalize(params)
    req = Net::HTTP::Post.new(URI(@pushtokens_uri.to_s+".json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(@pushtokens_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def delete_push_token(push_token_id)
    @token = get_token("user_device") unless @token_type=='user_device'
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/push_tokens/#{push_token_id}?token=#{@token}")
    response = http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_subscription (channels, url=nil)
    @token = get_token("user_device") unless @token_type=='user_device'
    hash={:notification_channels => "#{channels}", :url => "#{url}"}
    hash.merge! "token" => @token
    normalized= normalize(hash)
    req = Net::HTTP::Post.new(URI("http://"+@server.to_s+"/subscriptions.json").path)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def get_subscriptions
    @token = get_token("user_device") unless @token_type=='user_device'
    subscriptions = Net::HTTP.get_response(URI("http://"+@server.to_s+"/subscriptions.json?token=#{@token}"))
    JSON.parse(subscriptions.body)
  end

  def delete_subscription(id)
    @token = get_token("user_device") unless @token_type=='user_device'
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/subscriptions/#{id}/?token=#{@token}")
    response=http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_event(params, message, custom_params = {})
    @token = get_token("user_device") unless @token_type=='user_device'
    if params[:event][:notification_type]=="push"
      if params[:event][:push_type]=="mpns"
        if message[:type]=="toast"
          mpns_body="<?xml version='1.0' encoding='utf-8'?>"+
              "<wp:Notification xmlns:wp='WPNotification'>"+
              "<wp:Toast>"+
              "<wp:Text1>#{message[:head]}</wp:Text1>"+
              "<wp:Text2>#{message[:body]}</wp:Text2>"+
              "<wp:Param>#{message[:return_path]}</wp:Param>"+
              "</wp:Toast>"+
              "</wp:Notification>"

          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]},X-WindowsPhone-Target,toast")) rescue nil
        end

        if message[:type]=="tile"
          mpns_body="<?xml version='1.0' encoding='utf-8'?>" +
              "<wp:Notification xmlns:wp='WPNotification'>" +
              "<wp:Tile>" +
              "<wp:BackgroundImage>#{message[:background_image]}></wp:BackgroundImage>" +
              "<wp:Count>#{message[:count]}</wp:Count>" +
              "<wp:Title>#{message[:title]}</wp:Title>" +
              "<wp:BackBackgroundImage>#{message[:back_background_image]}</wp:BackBackgroundImage>"+
              "<wp:BackTitle>#{message[:back_title]}</wp:BackTitle>"+
              "<wp:BackContent>#{message[:back_content]}</wp:BackContent>"+
              "</wp:Tile>" +
              "</wp:Notification>"
          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]},X-WindowsPhone-Target,token")) rescue nil

        end

        if message[:type]=="raw"
          mpns_body=message[:body]
          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]}")) rescue nil

        end
      end

      if params[:event][:push_type]=="apns"
        to_send=CGI::escape("payload=" + Base64.strict_encode64(({:aps => {:alert => message[:alert], :badge => message[:badge_counter].to_i || 1, :sound => message[:sound] || 'default'}}.merge(custom_params)).to_json).to_s) rescue nil
      end

      if params[:event][:push_type]=="gcm"
        encoded_custom_params = ''

        custom_params.each do |key, value|
          encoded_custom_params += ("&data.#{key}=" + CGI::escape(Base64.strict_encode64(value).to_s))
        end

        to_send=CGI::escape("data.message=" + CGI::escape(Base64.strict_encode64(message[:body]).to_s) + encoded_custom_params)
      end

      if params[:event][:push_type]==nil
        to_send=Base64.strict_encode64(message[:body]).to_s
      end
    end

    if params[:event][:notification_type]=="email"|| params[:event][:notification_type]=="pull"
      to_send=CGI::escape("subject="+Base64.strict_encode64(message[:subject])+"&body="+Base64.strict_encode64(message[:body]).to_s) rescue nil
    end

    if params[:event][:notification_type]== "http_request"
      to_send=CGI::escape("subject=#{message[:subject]}&body=#{message[:body]}&#{message[:params]}".to_s) rescue nil
    end

    params.merge! "token" => @token
    normalized = normalize(params)
    req = Net::HTTP::Post.new(URI("http://"+@server.to_s+"/events.json").path)
    req.body = "#{normalized}&event[message]=#{to_send}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def get_events(page=1, per_page=10)
    @token = get_token("user_device") unless @token_type=='user_device'
    file_info = Net::HTTP.get_response(URI("http://"+@server.to_s+"/events.json")+"?token=#{@token}&per_page=#{per_page}&page=#{page}")
    JSON.parse(file_info.body)
  end

  def edit_event(id, params, message=nil)
    @token = get_token("user_device") unless @token_type=='user_device'
    event=get_event_by_id(id)
    notification=event["notification_channel"]["name"]
    params.merge! "token" => @token
    normalized = normalize(params)
    req = Net::HTTP::Put.new(URI("http://"+@server.to_s+"/events/#{id}.json").path)
    if message
      if notification=="mpns"
        if message[:type]=="toast"
          mpns_body="<?xml version='1.0' encoding='utf-8'?>"+
              "<wp:Notification xmlns:wp='WPNotification'>"+
              "<wp:Toast>"+
              "<wp:Text1>#{message[:head]}</wp:Text1>"+
              "<wp:Text2>#{message[:body]}</wp:Text2>"+
              "<wp:Param>#{message[:return_path]}</wp:Param>"+
              "</wp:Toast>"+
              "</wp:Notification>"

          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]},X-WindowsPhone-Target,toast")) rescue nil
        end


        if message[:type]=="tile"
          mpns_body="<?xml version='1.0' encoding='utf-8'?>" +
              "<wp:Notification xmlns:wp='WPNotification'>" +
              "<wp:Tile>" +
              "<wp:BackgroundImage>#{message[:background_image]}></wp:BackgroundImage>" +
              "<wp:Count>#{message[:count]}</wp:Count>" +
              "<wp:Title>#{message[:title]}</wp:Title>" +
              "<wp:BackBackgroundImage>#{message[:back_background_image]}</wp:BackBackgroundImage>"+
              "<wp:BackTitle>#{message[:back_title]}</wp:BackTitle>"+
              "<wp:BackContent>#{message[:back_content]}</wp:BackContent>"+
              "</wp:Tile>" +
              "</wp:Notification>"

          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]},X-WindowsPhone-Target,token")) rescue nil

        end

        if message[:type]=="raw"
          mpns_body=message[:body]
          to_send=CGI::escape("mpns="+Base64.strict_encode64(mpns_body)+"&headers="+Base64.strict_encode64("Content-Type,text/xml,X-NotificationClass,#{message[:class]}")) rescue nil

        end
      end


      if notification=="apns"
        to_send="payload=" + Base64.strict_encode64({:aps => {:alert => message[:alert], :badge => message[:badge_counter].to_i || 1, :sound => message[:sound] || 'default'}}.to_json).to_s rescue nil
      end

      if notification=="gcm"
        to_send="data.message=" + Base64.strict_encode64(message[:body]).to_s
      end

      if notification=="http_request" || message[:type]== "email" || message[:type]=="pull"
        to_send=Base64.strict_encode64(message[:body]).to_s
      end

      if notification=="email"|| notification=="pull"
        to_send=CGI::escape("subject="+Base64.strict_encode64(message[:subject])+"&body="+Base64.strict_encode64(message[:body]).to_s) rescue nil
      end

      if notification=="http_request"
        to_send=CGI::escape("subject=#{message[:subject]}&body=#{message[:body]}&#{message[:params]}".to_s) rescue nil
      end

      req.body = "#{normalized}&event[message]=#{to_send}"
    else
      req.body = "#{normalized}"
    end
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def delete_event(id)
    @token = get_token("user_device") unless @token_type=='user_device'
    http = Net::HTTP.new(@server)
    delete_event = Net::HTTP::Delete.new("/events/#{id}?token=#{@token}")
    response=http.request(delete_event)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def get_event_by_id(id)
    @token = get_token("user_device") unless @token_type=='user_device'
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/events/#{id}.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_pull_request_list
    @token = get_token("user_device") unless @token_type=='user_device'
    event = Net::HTTP.get_response(URI("http://"+@server.to_s+"/pull_events.json?token=#{@token}"))
    JSON.parse(event.body)
  end

# Ratings API requests

  def create_gamemode(title)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Post.new(URI(@gamemodes_uri.to_s+".json").path)
    req.body = "token=#{@token}&gamemode[title]=#{title}"
    response=Net::HTTP.start(@pushtokens_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def update_gamemode(id, title)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI(@gamemodes_uri.to_s+"/#{id}.json").path)
    req.body = "token=#{@token}&gamemode[title] =#{title}"
    response=Net::HTTP.start(@pushtokens_uri.host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)["game_mode"]
  end

  def get_gamemode_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI(@gamemodes_uri.to_s+"/#{id}.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_gamemodes
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/application/gamemodes.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_gamemode(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/gamemodes/#{id}?token=#{@token}")
    response = http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_score(params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Post.new(URI("http://"+@server.to_s+"/scores.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)

  end

  def update_score(id, params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI("http://"+@server.to_s+"/scores/#{id}.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_score_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/scores/#{id}.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_top_scores(id, count=10, page=1, per_page=10, filters=nil, sort=1)
    @token = get_token("user") unless @token_type=='user'
    response = Net::HTTP.get_response(URI(@gamemodes_uri.to_s+"/#{id}/top.#{count}.json?token=#{@token}&page=#{page}&per_page=#{per_page}&sort=#{sort}&filters=#{filters}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_scores_for_user(id, sort_by="value", filters=nil, sort=1)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/users/#{id}/scores.json?token=#{@token}&sort=#{sort}&filters=#{filters}&sort_by=#{sort_by}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_average_scores(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI(@gamemodes_uri.to_s+"/#{id}/average.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_average_scores_by_app
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/application/averages.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_score(id)
    @token = get_token("user") unless @token_type=='user'
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/scores/#{id}?token=#{@token}")
    response = http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_gamemodeparameter(params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Post.new(URI("http://"+@server.to_s+"/gamemodeparameters.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def update_gamemodeparameter(id, params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI("http://"+@server.to_s+"/gamemodeparameters/#{id}.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_gamemodeparameter_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/gamemodeparameters/#{id}.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_gamemodeparameter_by_gamemode_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI(@gamemodes_uri.to_s+"/#{id}/gamemodeparameters.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_gamemodeparameter(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/gamemodeparameters/#{id}?token=#{@token}")
    response = http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end

  def create_gamemodeparametervalue(params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Post.new(URI("http://"+@server.to_s+"/gamemodeparametervalues.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "201"
    JSON.parse(response.body)
  end

  def update_gamemodeparametervalue(id, params)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    req = Net::HTTP::Put.new(URI("http://"+@server.to_s+"/gamemodeparametervalues/#{id}.json").path)
    params.merge! "token" => @token
    normalized = normalize(params)
    req.body = "#{normalized}"
    response=Net::HTTP.start(URI("http://"+@server.to_s).host) do |http|
      http.request(req)
    end
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_gamemodeparametervalue_by_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/gamemodeparametervalues/#{id}.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_gamemodeparametervalue_by_score_id(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/scores/#{id}/gamemodeparametervalues.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def get_api_gamemodeparametervalue_by_score_id(score_id, para_id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    response = Net::HTTP.get_response(URI("http://"+@server.to_s+"/scores/#{score_id}/gamemodeparameters/#{para_id}/value.json?token=#{@token}"))
    return {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)} unless response.code == "200"
    JSON.parse(response.body)
  end

  def delete_gamemodeparametervalue(id)
    @token = get_token("user") unless @token_type=='user'
    return "ERROR: No user is logged in" unless @user_id
    http = Net::HTTP.new(@server)
    delete = Net::HTTP::Delete.new("/gamemodeparametervalues/#{id}?token=#{@token}")
    response=http.request(delete)
    {:response_code => response.code, :response_header => response, :response_body => (JSON.parse(response.body) rescue nil)}
  end


  module HashConverter

    def self.encode(value, key = nil, out_hash = {})
      case value
        when Hash then
          value.each { |k, v| encode(v, append_key(key, k), out_hash) }
          out_hash
        when Array then
          value.each { |v| encode(v, "#{key}[]", out_hash) }
          out_hash
        when nil then
          ''
        else
          out_hash[key] = value
          out_hash
      end
    end

    private

    def self.append_key(root_key, key)
      root_key.nil? ? :"#{key}" : :"#{root_key}[#{key.to_s}]"
    end

  end

  def normalize (var)
    var = HashConverter.encode(var)
    var.collect { |k, v|
      if v.is_a? Hash
        v.collect { |k1, v1| "#{k}[#{k1}]=#{v1}" }.sort.join('&')
      else
        "#{k}=#{v}"
      end
    }.sort.join('&')
  end


end
