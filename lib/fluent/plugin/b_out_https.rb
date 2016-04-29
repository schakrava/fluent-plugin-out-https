class Fluent::BHTTPSOutput < Fluent::BufferedOutput
    # First, register the plugin. NAME is the name of this plugin
    # and identifies the plugin in the configuration file.
    Fluent::Plugin.register_output('bhttp', self)

    def initialize
      super
      require 'yajl'
      require 'net/https'
      require 'openssl'
      require 'uri'
    end

    # config_param defines a parameter. You can refer a parameter via @path instance variable
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

    config_param :ca, :string
    config_param :key, :string
    config_param :cert, :string
    # This method is called before starting.
    # 'conf' is a Hash that includes configuration parameters.
    # If the configuration is invalid, raise Fluent::ConfigError.
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

    # This method is called when starting.
    # Open sockets or files here.
    def start
      super
    end

    # This method is called when shutting down.
    # Shutdown the thread and close sockets or files here.
    def shutdown
      super
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

    # This method is called when an event reaches to Fluentd.
    # Convert the event to a raw string.
    def format(tag, time, record)
      record['timestamp'] = Time.now.to_i
      cpu_data = cpu_stats(record)
      #we append \n to the json string to use it as a separator to split the
      #string and reconstruct a list of metrics to POST at once.
      cpu_data.to_json + "\n"
    end

    #opentsdb recomments a maximum of 50 metrics in one request.  keepalive not
    #necessary because this plugin will be called once every 30 seconds or more.
    #we might want to enable chunk support in opentsdb?
    #http://opentsdb.net/docs/build/html/api_http/put.html
    def create_request(record)
      uri = URI.parse(@endpoint_url)
      req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.path)
      req.body = record
      req['Content-Type'] = 'application/json'
      #$log.info("body #{req.body}")
      return req, uri
    end

    # This method is called every flush interval. Write the buffer chunk
    # to files or databases here.
    # 'chunk' is a buffer chunk that includes multiple formatted
    # events. You can use 'data = chunk.read' to get all events and
    # 'chunk.open {|io| ... }' to get IO objects.
    #
    # NOTE! This method is called by internal thread, not Fluentd's main thread. So IO wait doesn't affect other plugins.
    def write(chunk)
      begin
        data = chunk.read
        data_array = data.split("\n")
        fin_data = []
        data_array.each { |d|
          rd = JSON.parse(d)
          fin_data += rd
        }
        fin_data = fin_data.to_json
        #$log.info("data #{fin_data}")
        req, uri = create_request(fin_data)
        https = Net::HTTP.new(uri.host, uri.port)
        https.use_ssl = @use_ssl
        https.ca_file = @ca
        https.key = OpenSSL::PKey::RSA.new File.read @key
        https.cert = OpenSSL::X509::Certificate.new File.read @cert
        https.verify_mode = OpenSSL::SSL::VERIFY_NONE
        res = https.start {|http| http.request(req) }
      rescue IOError, EOFError, SystemCallError
        $log.error "Net::HTTP.#{req.method.capitalize} raises exception: #{$!.class}, '#{$!.message}'"
        raise
      end
      unless res and res.is_a?(Net::HTTPSuccess)
        res_summary = if res
                        "#{res.code} #{res.message} #{res.body}"
                      else
                        "res=nil"
                      end
        emsg = "failed to #{req.method} #{uri} (#{res_summary})"
        $log.error emsg
        raise emsg
      end
    end
end
