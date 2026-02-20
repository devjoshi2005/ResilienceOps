data "aws_ami" "amazon_linux"{
    most_recent = true 
    owners=["amazon"]
    filter{
        name="name"
        values=["amzn2-ami-hvm-*-x86_64-gp2"]
    }
}
resource "aws_security_group" "observability"{
    name_prefix = "resilienceops-"
    ingress{
        from_port = 22 
        to_port = 22 
        protocol = "tcp"
        cidr_blocks=["0.0.0.0/0"]
        description = "SSH"
    }
    ingress{
        from_port = 9090 
        to_port = 9090 
        protocol = "tcp"
        cidr_blocks=["0.0.0.0/0"]
        description = "Prometheus"
    }
    ingress{
        from_port = 3000 
        to_port = 3000 
        protocol = "tcp"
        cidr_blocks=["0.0.0.0/0"]
        description = "grafana"
    }
    ingress{
        from_port = 9100 
        to_port = 9100 
        protocol = "tcp"
        cidr_blocks=["0.0.0.0/0"]
        description = "Node exporter metrics"
    }
    egress{
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags={
        Name="resilienceops-observability"
        Project="ResilienceOps"
    }
}
resource "aws_instance" "observability"{
    ami = data.aws_ami.amazon_linux.id 
    instance_type = "t3.medium"
    vpc_security_group_ids = [aws_security_group.observability.id]
    user_data = <<-EOF
              #!/bin/bash
              set -e

              # Update system
              yum update -y

              # Install Docker
              amazon-linux-extras install docker -y
              systemctl start docker
              systemctl enable docker
              usermod -aG docker ec2-user

              # Install Docker Compose
              curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
              chmod +x /usr/local/bin/docker-compose

              # Create docker-compose directory
              mkdir -p /opt/resilienceops
              cd /opt/resilienceops

              # Write docker-compose.yml
              cat > docker-compose.yml <<'DOCKER'
              version: '3.8'

              services:
                prometheus:
                  image: prom/prometheus:v2.47.0
                  container_name: prometheus
                  ports:
                    - "9090:9090"
                  volumes:
                    - ./prometheus.yml:/etc/prometheus/prometheus.yml
                    - prometheus_data:/prometheus
                  command:
                    - '--config.file=/etc/prometheus/prometheus.yml'
                    - '--storage.tsdb.path=/prometheus'
                    - '--web.enable-lifecycle'

                grafana:
                  image: grafana/grafana:10.1.0
                  container_name: grafana
                  ports:
                    - "3000:3000"
                  volumes:
                    - grafana_data:/var/lib/grafana
                  environment:
                    - GF_SECURITY_ADMIN_PASSWORD=resilienceops123
                    - GF_INSTALL_PLUGINS=grafana-clock-panel

                node-exporter:
                  image: prom/node-exporter:v1.6.1
                  container_name: node-exporter
                  ports:
                    - "9100:9100"
                  volumes:
                    - /proc:/host/proc:ro
                    - /sys:/host/sys:ro
                    - /:/rootfs:ro

              volumes:
                prometheus_data:
                grafana_data:
              DOCKER

              # Write prometheus config
              cat > prometheus.yml <<'PROM'
              global:
                scrape_interval: 15s

              scrape_configs:
                - job_name: 'prometheus'
                  static_configs:
                    - targets: ['localhost:9090']

                - job_name: 'node-exporter'
                  static_configs:
                    - targets: ['node-exporter:9100']
              PROM

              # Start services
              docker-compose up -d

              echo "ResilienceOps observability stack deployed!"
              echo "Prometheus: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):9090"
              echo "Grafana: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):3000"
              EOF
    tags={
        Name="resilienceops-observability"
        Project="ResilienceOps"
        Environment="demo"
    }
}
