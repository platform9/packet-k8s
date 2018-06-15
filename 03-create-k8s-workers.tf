data "template_file" "worker_cloud_init" {
  template = "${file("configs/worker_node.conf")}"
  vars {
    PF9_Account_Endpoint = "${var.PF9_Account_Endpoint}"
    OS_REGION_NAME       = "${var.OS_REGION_NAME}"
    OS_USERNAME          = "${var.OS_USERNAME}"
    OS_PASSWORD          = "${var.OS_PASSWORD}"
    CLUSTER_NAME         = "${var.cluster_name}"
  }
}

resource "packet_device" "k8s-worker" {
  count            = "${var.node_count}"
  hostname         = "${var.cluster_name}-worker-${count.index}"
  plan             = "${var.server_type}"
  facility         = "${var.facility}"
  operating_system = "${var.operating_system}"
  billing_cycle    = "hourly"
  project_id       = "${var.project_id}"
  user_data        = "${data.template_file.worker_cloud_init.rendered}"
}
 
