class Fluent::HTTPSOutput < Fluent::Output
  Fluent::Plugin.register_output('http', self)

  def initialize
    super
    require 'net/https'
    require 'openssl'
    require 'uri'
    require 'yajl'
  end

  # https or http
  config_param :use_ssl, :bool, :default => false

  # include tag
  config_param :include_tag, :bool, :default => false

  # include timestamp
  config_param :include_timestamp, :bool, :default => false

  # Endpoint URL ex. localhost.local/api/
  config_param :endpoint_url, :string

  # HTTP method
  config_param :http_method, :string, :default => :post

  # form | json
  config_param :serializer, :string, :default => :form

  # Simple rate limiting: ignore any records within `rate_limit_msec`
  # since the last one.
  config_param :rate_limit_msec, :integer, :default => 0

  # nil | 'none' | 'basic'
  config_param :authentication, :string, :default => nil
  config_param :username, :string, :default => ''
  config_param :password, :string, :default => ''

  def configure(conf)
    super

    @use_ssl = conf['use_ssl']
    @include_tag = conf['include_tag']
    @include_timestamp = conf['include_timestamp']

    serializers = [:json, :form]
    @serializer = if serializers.include? @serializer.intern
                    @serializer.intern
                  else
                    :form
                  end

    http_methods = [:get, :put, :post, :delete]
    @http_method = if http_methods.include? @http_method.intern
                    @http_method.intern
                  else
                    :post
                  end

    @auth = case @authentication
            when 'basic' then :basic
            else
              :none
            end
  end

  def start
    super
  end

  def shutdown
    super
  end

  def format_url(tag, time, record)
    @endpoint_url
  end

  def set_body(req, tag, time, record)
    if @include_tag
      record['tag'] = tag
    end
    if @include_timestamp
      record['timestamp'] = Time.now.to_i
    end
    if @serializer == :json
      set_json_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    req
  end

  #return a multimetric input structure.
  #[
  #    "metric": "totoal-cpu-usr",
  #    "timestamp": data["timestamp"],
  #    "value": cpu_data["usr"],
  #    "tags": {
  #        "hostname" = data["hostname"]
  #    },
  #    "metric": "total-cpu-sys",
  #    "timestamp": data["timestamp"],
  #    "value": cpu_data["sys"],
  #    "tags": {
  #        "hostname" = data["hostname"],
  #    }
  #   and so on...
  #]
  def cpu_stats(data)
    cpu_data = data["dstat"]["total_cpu_usage"]
    ret = []
    cpu_data.each { |k, v|
      cur_metric = {
        "metric" => "total-cpu-" + k,
        "value" => v,
        "timestamp" => data["timestamp"],
        "tags" => {"hostname" => data["hostname"]}
      }
      ret.push(cur_metric)
    }
    return ret
  end

  def set_json_body(req, data)
    $log.info("data #{data}")
    req.body = Yajl.dump(cpu_stats(data))
    req['Content-Type'] = 'application/json'
  end

  #opentsdb recomments a maximum of 50 metrics in one request.  keepalive not
  #necessary because this plugin will be called once every 30 seconds or more.
  #we might want to enable chunk support in opentsdb?
  #http://opentsdb.net/docs/build/html/api_http/put.html
  def create_request(tag, time, record)
    url = format_url(tag, time, record)
    uri = URI.parse(url)
    req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.path)
    set_body(req, tag, time, record)
    $log.info("body #{req.body}")
    set_header(req, tag, time, record)
    return req, uri
  end

  def send_request(req, uri)
    is_rate_limited = (@rate_limit_msec != 0 and not @last_request_time.nil?)
    if is_rate_limited and ((Time.now.to_f - @last_request_time) * 1000.0 < @rate_limit_msec)
      $log.info('Dropped request due to rate limiting')
      return
    end

    res = nil
    begin
      if @auth and @auth == :basic
        req.basic_auth(@username, @password)
      end
      @last_request_time = Time.now.to_f
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = @use_ssl
      https.ca_file = '/persist/etc/esi/ca'
      https.key = OpenSSL::PKey::RSA.new File.read '/etc/td-agent/key'
      https.cert = OpenSSL::X509::Certificate.new File.read '/persist/etc/esi/cert'
      #https.ca_file = OpenSSL::X509::DEFAULT_CERT_FILE
#      https.verify_mode = OpenSSL::SSL::VERIFY_PEER
      https.verify_mode = OpenSSL::SSL::VERIFY_NONE
      res = https.start {|http| http.request(req) }
    rescue IOError, EOFError, SystemCallError
      # server didn't respond
      $log.warn "Net::HTTP.#{req.method.capitalize} raises exception: #{$!.class}, '#{$!.message}'"
    end
    unless res and res.is_a?(Net::HTTPSuccess)
      res_summary = if res
                      "#{res.code} #{res.message} #{res.body}"
                    else
                      "res=nil"
                    end
      $log.warn "failed to #{req.method} #{uri} (#{res_summary})"
    end
  end

  def handle_record(tag, time, record)
    req, uri = create_request(tag, time, record)
    send_request(req, uri)
  end

  def emit(tag, es, chain)
    es.each do |time, record|
      handle_record(tag, time, record)
    end
    chain.next
  end
end
