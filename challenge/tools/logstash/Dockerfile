FROM docker.elastic.co/logstash/logstash-oss:7.2.0
RUN rm -f /usr/share/logstash/pipeline/logstash.conf
ADD pipelines /usr/share/logstash/pipeline
ADD pipeline.yml /usr/share/logstash/config/pipelines.yml