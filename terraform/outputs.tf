output "observability_ip"{
    value=aws_instance.observability.public_ip
    description = "public ip of observability server"
}
output "grafana_url"{
    value="http://${aws_instance.observability.public_ip}:3000"
    description = "Grafana URL"
}
output "prometheus_url"{
    value="http://${aws_instance.observability.public_ip}:9090"
    description="Prometheus URL"
}