Logstash patterns and conf for parsing and storing maillogs.  

With Logstash, you'll also need input and output specified and saved under conf.d. Below is an example input-output-config.

```
input {  
  # For standard maillog sent from rsyslogd or syslog-ng.  
  syslog {  
    type => "mailserver-log"  
    port => "9473"  
  }  
  
  # For a bit more secure transport you can use Lumberjack.  
  # Find out more at https://www.elastic.co/guide/en/logstash/current/plugins-inputs-lumberjack.html  
  lumberjack {  
    port => "9474"  
    type => "mailserver-log"  
    ssl_certificate => "/etc/logstash/ssl/logstash-forwarder.crt"  
    ssl_key => "/etc/logstash/ssl/logstash-forwarder.key"  
  }  
}  

output {  
  # You can also use standard Elasticsearch plugin!  
  # Find out more at https://www.elastic.co/guide/en/logstash/current/plugins-outputs-elasticsearch.html  
  elasticsearch_http {  
    host => "your.elasticsearch.server"  
  }  
  
  # For debugging  
  # file {  
  #   path => "/var/log/logstash/logstash-debug.log"  
  # }  
}  
``` 
