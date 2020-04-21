# Example Configurations for Logstash

## Inputs

### File Input

It is uncommon to use logstash to directly tail files.  This is generally done using a small agent application called a `Beat`.  
If you have chosen to not use the beat architecture you can have logstash tail a file very simply.  It is a good idea to label
logs with types and tags to make it easier for you to identify their source and allows you to develop more complex log processing
pipelines as you become a more sophisticated user.

```
input {
  file {
    path => "/var/log/nginx.log"
    type => "nginx"
    start_position => "beginning"
  }
}

```

For more configuration details on the logstash file input plugin can be found [here.](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-file.html)

### Syslog

This by default will listen on `0.0.0.0` and port 514 for incoming syslog udp messages.  You can additionally configure it to parse custom syslog
formats and extract timestamps.  Further details on configuration can be found [here.](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-syslog.html)

```
input {
  syslog {
    port => 12345
    type => 'syslog-forwarded'
  }
}
```

### Beats

Recieving data forwarded by beats is the standard and preferred way to forward data to a logstash instance.  Beats are lightweight processes that run alongside your application and 
collect and forward logs to logstash for parsing and aggregation.  They have a very light resource footprint and support can pull logs from my different sources.

- [files](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-overview.html)
- [journald](https://www.elastic.co/guide/en/beats/journalbeat/current/journalbeat-overview.html)
- [syslog](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-syslog.html)


```
input {
  beats {
    port => 5044
  }
}
```
## Adding Fields

There are some attributes that can be included which will make searching logs easier as well as understanding the source of the logs easier. To do this we can use a filter that calls the [add_field](https://www.elastic.co/guide/en/logstash/current/plugins-filters-mutate.html#plugins-filters-mutate-add_field) function. Logtype is an important field to add; it helps filter and organize your log data as well as link to parsing rules.

```
filter {
      mutate {
        add_field => {
          "logtype" => "nginx"
          "service_name" => "myservicename"
          "hostname" => "%{host}"
        }
      }
    }
```

## Parsing

Logstash has some fairly advanced parsing capabilities that allow you to structure your unstructured log lines and extract the fields that you might want to search on.  It also allows
you to get more accurate timestamps by parsing them directly from the log line.

Let's consider parsing an AWS Elastic Load Balancer log into a more structured format.

```2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0" DHE-RSA-AES128-SHA TLSv1.2```

So we have a bunch of fields here separated by spaces that we may want to search across.  How do we break this down?  

### Grok to the rescue

Grok is a hybrid parsing language that is based on regular expressions.  It allows people less familiar with regular expressiosn to harness their power to write fairly sophisticated 
parsers without a great deal of work.  Logstash comes with a nice library of useful patterns and allows you to extend it by writing your own.

#### Anatomy of a grok rule

Grok rules consist of a pattern to match a term and optionally a name to capture the results at.

Ex:

```%{IP:client_ip}```

This would match a pattern like `10.0.0.1` and store the matched value in an attribute called `client_ip`.

So lets disect a full grok parsing rule for this log format.

```
%{TIMESTAMP_ISO8601:timestamp} %{GREEDYDATA:elb_name} %{IP:client_ip}:%{NUMBER:client_port} %{IP:backend_ip}:%{NUMBER:backend_port} %{NUMBER:request_processing_time} %{NUMBER:backend_processing_time} %{NUMBER:response_processing_time} %{NUMBER:elb_status_code} %{NUMBER:backend_status_code} %{NUMBER:received_bytes} %{NUMBER:sent_bytes} %{QUOTEDSTRING:request} %{QUOTEDSTRING:user_agent} %{GREEDYDATA:ssl_cipher} %{GREEDYDATA:ssl_protocol}
```

This seems pretty dense at first but we can unravel it pretty easily.

Lets first look at the underlying format of the log message

```timestamp elb client:port backend:port request_processing_time backend_processing_time response_processing_time elb_status_code backend_status_code received_bytes sent_bytes "request" "user_agent" ssl_cipher ssl_protocol```

The first thing we are going to want to parse out is the timestamp.  Logstash has built in patterns for a lot of common timestamp formats.  You can define write your own custom formats if one is not available.  If you want to check a list of the existing timestamp formats check [here](https://github.com/elastic/logstash/blob/v1.4.2/patterns/grok-patterns).  Fortunately this is a simple ISO8601 timestamp so we are already covered.  

Then we move on to parsing the load balancers name.  You can for sure write a more precise regex for this if you feel so inclined but I have opted to use the `GREEDYDATA` format to capture words of mixed characters for this example.  I would recommend writting more efficient regular expressions if you are comfortable doing so.  

We then have our client ip and port and internal backend ip and port.  There are existing patterns for IPV4 and v6 ips and hostnames which makes this pretty easy with the following fragment
```
%{IP:client_ip}:%{NUMBER:client_port} %{IP:backend_ip}:%{NUMBER:backend_port}
```

We then have a bunch of numbers to extract for the request_processing_time backend_processing_time, elb_status_code, backend_status_code, received_bytes, and sent_bytes.  We can do this using the `%{NUMBER}` pattern.  

```
%{NUMBER:request_processing_time} %{NUMBER:backend_processing_time} %{NUMBER:response_processing_time} %{NUMBER:elb_status_code} %{NUMBER:backend_status_code} %{NUMBER:received_bytes} %{NUMBER:sent_bytes}
```

We have a few quoted strings for the request and user agent also that we would want to extract using the `%{QUOTEDSTRING}` rule.

```
%{QUOTEDSTRING:request} %{QUOTEDSTRING:user_agent}
```

Finally we have the SSL Information for the cipher and protocol

```
%{GREEDYDATA:ssl_cipher} %{GREEDYDATA:ssl_protocol}
```

At this point we have a fully structured log message with all the facets we may want to search on extracted.
