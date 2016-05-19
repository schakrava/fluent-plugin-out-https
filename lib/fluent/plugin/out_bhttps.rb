class Fluent::BHTTPSOutput < Fluent::BufferedOutput
    # First, register the plugin. NAME is the name of this plugin
    # and identifies the plugin in the configuration file.
    Fluent::Plugin.register_output('bhttps', self)

    def initialize
      super
      require 'yajl'
      require 'net/https'
      require 'openssl'
      require 'uri'
      require 'objspace'
      require 'zlib'
      require 'stringio'
    end

    # config_param defines a parameter. You can refer a parameter via @path instance variable
    # https or http
    config_param :use_ssl, :bool, :default => false

    # include timestamp
    config_param :include_timestamp, :bool, :default => false

    # Endpoint URL ex. localhost.local/api/
    config_param :endpoint_url, :string

    # HTTP method
    config_param :http_method, :string, :default => :post

    # form | json
    config_param :serializer, :string, :default => :form

    # gzip
    config_param :compression, :string, :default => nil

    # Simple rate limiting: ignore any records within `rate_limit_msec`
    # since the last one.
    config_param :rate_limit_msec, :integer, :default => 0

    # maximum payload size.
    config_param :max_payload, :integer, :default => 4096

    # nil | 'none' | 'basic'
    #not implemented atm.
    config_param :authentication, :string, :default => nil
    config_param :username, :string, :default => ''
    config_param :password, :string, :default => ''

    config_param :ca, :string
    config_param :key, :string
    config_param :cert, :string

    #devconfig is read from the ese to get device id and name for tagging
    #metrics with.
    config_param :devconfig, :string, :default => '/persist/etc/esi/device.json'

    # This method is called before starting.
    # 'conf' is a Hash that includes configuration parameters.
    # If the configuration is invalid, raise Fluent::ConfigError.
    def configure(conf)
      super

      @use_ssl = conf['use_ssl']
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
      #number of cores in the system to appropriately
      #parse dstat output and tag cpu metrics by core.
      @num_cpu_cores = Integer(%x["/usr/bin/nproc"].strip)

      #device metadata to add to tags.
      @device_data = JSON.parse(File.read(@devconfig))

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

    #Convert dstat reported cpu metrics into tsdb friendly format with agreed
    #upon tags. This method returns an array of metrics, where each metric has
    #the following structure.
    # {
    #    "metric": "cpu.<usr|sys|idl|wai>",
    #    "timestamp": data["timestamp"],
    #    "value": <metric_value>,
    #    "tags": {
    #        "hostname": data["hostname"],
    #        "resource_id": <device_id>,
    #        "resource_name": <device_name>,
    #        "core": <cpu_core_number>,
    #        "tenant_id": <gohan_tenant_id>
    #    }
    # }
    #@todo: for now gohan tenant id is hard coded to "admin". But as we resolve
    #ESI-8188, we'll update this boilerplate code.
    def cpu_stats(data)
      for i in 0..@num_cpu_cores-1
        cpu_data = data["dstat"]["cpu#{i}_usage"]
        $log.info "core num = #{i}. data = #{cpu_data}"
        ret = []
        cpu_data.each { |k, v|
          cur_metric = {
            "metric" => "cpu.#{k}",
            "value" => v,
            "timestamp" => data["timestamp"],
            "tags" => {"resource_id" => @device_data["id"],
                       "resource_name" => @device_data["name"],
                       "hostname" => data["hostname"],
                       "core" => i,
                       "tenant_id" => "admin"}
          }
          ret.push(cur_metric)
        }
      end
      return ret
    end

    # This method is called when an event reaches to Fluentd.
    # Convert the event to a raw string.
    def format(tag, time, record)
      if @include_timestamp
        record['timestamp'] = Time.now.to_i
      end
      if @serializer == :json
        cpu_data = cpu_stats(record)
        #we append \n to the json string to use it as a separator to split the
        #string and reconstruct a list of metrics to POST at once.
        return cpu_data.to_json + "\n"
      else
        raise "Only json serializer is supported"
      end
    end

    #opentsdb recomments a maximum of 50 metrics in one request.  keepalive not
    #necessary because this plugin will be called once every 30 seconds or more.
    #we might want to enable chunk support in opentsdb?
    #http://opentsdb.net/docs/build/html/api_http/put.html
    def create_request
      uri = URI.parse(@endpoint_url)
      req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.path)
      if @serializer == :json
        req['Content-Type'] = 'application/json'
      end
      https = Net::HTTP.new(uri.host, uri.port)
      if @use_ssl
        https.use_ssl = @use_ssl
        https.ca_file = @ca
        https.key = OpenSSL::PKey::RSA.new File.read @key
        https.cert = OpenSSL::X509::Certificate.new File.read @cert
        # this is insecure. try verify_peer?
        https.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
      #$log.info("body #{req.body}")
      return https, req
    end

    # This method is called every flush interval. Write the buffer chunk
    # to files or databases here.
    # 'chunk' is a buffer chunk that includes multiple formatted
    # events. You can use 'data = chunk.read' to get all events and
    # 'chunk.open {|io| ... }' to get IO objects.
    #
    # NOTE! This method is called by internal thread, not Fluentd's main thread. So IO wait doesn't affect other plugins.
    def write(chunk)
      $log.info("buffer chunk size: #{chunk.size}")
      begin
        https, req = create_request()
        data = chunk.read
        data_array = data.split("\n")
        fin_data = []
        size = 0
        data_array.each { |d|
          size += ObjectSpace.memsize_of(d)
          rd = JSON.parse(d)
          if size >= @max_payload
            $log.warn("content size exceeded #{@max_payload}. Flushing metrics.")
            send_metrics(https, req, fin_data.to_json)
            fin_data = []
            size = ObjectSpace.memsize_of(d)
          end
          fin_data += rd
        }
        send_metrics(https, req, fin_data.to_json)
        $log.info("metrics sent. size = #{size}")
      end
    end

    def send_metrics(https, request, data)
      begin
        if @compression
          if @compression != 'gzip'
            emsg = "Unsupported compression method(#{@compression}). Only gzip is supported"
            raise emsg
          end
          request['Content-Encoding'] = @compression
          sio = StringIO.new("w")
          sio_compressed = Zlib::GzipWriter.new(sio)
          sio_compressed.write(data)
          sio_compressed.close
          request.body = sio.string
        else
          request.body = data
        end
        res = https.start {|http| http.request(request) }
      rescue IOError, EOFError, SystemCallError
        $log.error "Net::HTTP.#{request.method.capitalize} raises exception: #{$!.class}, '#{$!.message}'"
        raise
      end
      unless res and res.is_a?(Net::HTTPSuccess)
        res_summary = if res
                        "#{res.code} #{res.message} #{res.body}"
                      else
                        "res=nil"
                      end
        emsg = "failed to #{request.method} (#{res_summary})"
        $log.error emsg
        raise emsg
      end
    end
end
