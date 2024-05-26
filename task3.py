ipvar HOME_NET any
ipvar EXTERNAL_NET any
var RULE_PATH /etc/snort/rules
include $RULE_PATH/community.rules
include $RULE_PATH/local.rules
output alert_fast: stdout
output unified2: filename snort.alert, limit 128

snort -A console -q -c /etc/snort/snort.conf -i eth0

input {
  file {
    path => "/var/log/snort/alert"
    type => "snort_alert"
  }
}
filter {
  grok {
    match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:snort_message}" }
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "snort-alerts-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}

alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; sid:1000001; rev:1;)

ping -c 
