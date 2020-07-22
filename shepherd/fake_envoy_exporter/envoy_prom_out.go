package main

// This is the output from querying
// curl -s -S http://envoy-ip:envoy-port/stats/prometheus
// The fake envoy exporter parses this to figure out what
// measurements to deliver. It replaces the cluster param but
// leaves other params alone.
// If the types of measurements that envoy exports changes, we
// can just recopy the output here.
var sampleOutput = `
# TYPE envoy_server_static_unknown_fields counter
envoy_server_static_unknown_fields{} 0
# TYPE envoy_cluster_manager_update_out_of_merge_window counter
envoy_cluster_manager_update_out_of_merge_window{} 0
# TYPE envoy_http_rq_direct_response counter
envoy_http_rq_direct_response{envoy_http_conn_manager_prefix="async-client"} 0
# TYPE envoy_http_downstream_cx_upgrades_total counter
envoy_http_downstream_cx_upgrades_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_rx_reset counter
envoy_http_downstream_rq_rx_reset{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_ssl_total counter
envoy_http_downstream_cx_ssl_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_rs_too_large counter
envoy_http_rs_too_large{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_rq_total counter
envoy_http_rq_total{envoy_http_conn_manager_prefix="async-client"} 0
# TYPE envoy_server_main_thread_watchdog_mega_miss counter
envoy_server_main_thread_watchdog_mega_miss{} 4
# TYPE envoy_server_watchdog_mega_miss counter
envoy_server_watchdog_mega_miss{} 12
# TYPE envoy_http_downstream_rq_overload_close counter
envoy_http_downstream_rq_overload_close{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_xx counter
envoy_http_downstream_rq_xx{envoy_response_code_class="1",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_destroy counter
envoy_http_downstream_cx_destroy{envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_runtime_override_dir_exists counter
envoy_runtime_override_dir_exists{} 0
# TYPE envoy_http_downstream_cx_protocol_error counter
envoy_http_downstream_cx_protocol_error{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_filesystem_reopen_failed counter
envoy_filesystem_reopen_failed{} 0
# TYPE envoy_http_downstream_cx_http3_total counter
envoy_http_downstream_cx_http3_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_flow_control_resumed_reading_total counter
envoy_http_downstream_flow_control_resumed_reading_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_rq_reset_after_downstream_response_started counter
envoy_http_rq_reset_after_downstream_response_started{envoy_http_conn_manager_prefix="async-client"} 0
# TYPE envoy_runtime_override_dir_not_exists counter
envoy_runtime_override_dir_not_exists{} 1
# TYPE envoy_server_watchdog_miss counter
envoy_server_watchdog_miss{} 20
# TYPE envoy_server_debug_assertion_failures counter
envoy_server_debug_assertion_failures{} 0
# TYPE envoy_cluster_manager_cluster_added counter
envoy_cluster_manager_cluster_added{} 1
# TYPE envoy_server_worker_0_watchdog_miss counter
envoy_server_worker_0_watchdog_miss{} 6
# TYPE envoy_server_worker_0_watchdog_mega_miss counter
envoy_server_worker_0_watchdog_mega_miss{} 5
# TYPE envoy_http_downstream_rq_too_large counter
envoy_http_downstream_rq_too_large{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_no_route counter
envoy_http_no_route{envoy_http_conn_manager_prefix="async-client"} 0
envoy_http_downstream_rq_xx{envoy_response_code_class="4",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_tx_bytes_total counter
envoy_http_downstream_cx_tx_bytes_total{envoy_http_conn_manager_prefix="admin"} 119457069
# TYPE envoy_http_downstream_cx_destroy_local_active_rq counter
envoy_http_downstream_cx_destroy_local_active_rq{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_filesystem_write_failed counter
envoy_filesystem_write_failed{} 0
# TYPE envoy_http_downstream_cx_overload_disable_keepalive counter
envoy_http_downstream_cx_overload_disable_keepalive{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_http2_total counter
envoy_http_downstream_rq_http2_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_max_duration_reached counter
envoy_http_downstream_cx_max_duration_reached{envoy_http_conn_manager_prefix="admin"} 0
envoy_http_downstream_rq_xx{envoy_response_code_class="5",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_filesystem_flushed_by_timer counter
envoy_filesystem_flushed_by_timer{} 1125
# TYPE envoy_http_downstream_cx_destroy_active_rq counter
envoy_http_downstream_cx_destroy_active_rq{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_cluster_manager_cluster_updated counter
envoy_cluster_manager_cluster_updated{} 0
# TYPE envoy_http_downstream_cx_http1_total counter
envoy_http_downstream_cx_http1_total{envoy_http_conn_manager_prefix="admin"} 4080
# TYPE envoy_http_downstream_cx_destroy_remote_active_rq counter
envoy_http_downstream_cx_destroy_remote_active_rq{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_total counter
envoy_http_downstream_rq_total{envoy_http_conn_manager_prefix="admin"} 4080
# TYPE envoy_filesystem_write_completed counter
envoy_filesystem_write_completed{} 1126
# TYPE envoy_server_dynamic_unknown_fields counter
envoy_server_dynamic_unknown_fields{} 0
# TYPE envoy_http_downstream_cx_rx_bytes_total counter
envoy_http_downstream_cx_rx_bytes_total{envoy_http_conn_manager_prefix="admin"} 367602
# TYPE envoy_http1_metadata_not_supported_error counter
envoy_http1_metadata_not_supported_error{} 0
# TYPE envoy_filesystem_write_buffered counter
envoy_filesystem_write_buffered{} 4079
# TYPE envoy_http_downstream_rq_timeout counter
envoy_http_downstream_rq_timeout{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_idle_timeout counter
envoy_http_downstream_cx_idle_timeout{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_drain_close counter
envoy_http_downstream_cx_drain_close{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_cluster_manager_cluster_removed counter
envoy_cluster_manager_cluster_removed{} 0
# TYPE envoy_cluster_manager_cluster_modified counter
envoy_cluster_manager_cluster_modified{} 0
# TYPE envoy_http_downstream_rq_ws_on_non_ws_route counter
envoy_http_downstream_rq_ws_on_non_ws_route{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_cluster_manager_cluster_updated_via_merge counter
envoy_cluster_manager_cluster_updated_via_merge{} 0
# TYPE envoy_runtime_deprecated_feature_use counter
envoy_runtime_deprecated_feature_use{} 1
# TYPE envoy_http_downstream_rq_http3_total counter
envoy_http_downstream_rq_http3_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_destroy_remote counter
envoy_http_downstream_cx_destroy_remote{envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_http_downstream_rq_non_relative_path counter
envoy_http_downstream_rq_non_relative_path{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_total counter
envoy_http_downstream_cx_total{envoy_http_conn_manager_prefix="admin"} 4080
# TYPE envoy_http_downstream_rq_tx_reset counter
envoy_http_downstream_rq_tx_reset{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_http2_total counter
envoy_http_downstream_cx_http2_total{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_server_worker_1_watchdog_miss counter
envoy_server_worker_1_watchdog_miss{} 5
# TYPE envoy_runtime_load_error counter
envoy_runtime_load_error{} 0
# TYPE envoy_http_downstream_rq_response_before_rq_complete counter
envoy_http_downstream_rq_response_before_rq_complete{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_no_cluster counter
envoy_http_no_cluster{envoy_http_conn_manager_prefix="async-client"} 0
envoy_http_downstream_rq_xx{envoy_response_code_class="3",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_completed counter
envoy_http_downstream_rq_completed{envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_http_rq_redirect counter
envoy_http_rq_redirect{envoy_http_conn_manager_prefix="async-client"} 0
# TYPE envoy_cluster_manager_update_merge_cancelled counter
envoy_cluster_manager_update_merge_cancelled{} 0
# TYPE envoy_http_downstream_rq_idle_timeout counter
envoy_http_downstream_rq_idle_timeout{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_server_main_thread_watchdog_miss counter
envoy_server_main_thread_watchdog_miss{} 9
# TYPE envoy_server_worker_1_watchdog_mega_miss counter
envoy_server_worker_1_watchdog_mega_miss{} 3
# TYPE envoy_http_downstream_rq_http1_total counter
envoy_http_downstream_rq_http1_total{envoy_http_conn_manager_prefix="admin"} 4080
# TYPE envoy_http_downstream_cx_delayed_close_timeout counter
envoy_http_downstream_cx_delayed_close_timeout{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_rq_retry_skipped_request_not_complete counter
envoy_http_rq_retry_skipped_request_not_complete{envoy_http_conn_manager_prefix="async-client"} 0
# TYPE envoy_http_downstream_flow_control_paused_reading_total counter
envoy_http_downstream_flow_control_paused_reading_total{envoy_http_conn_manager_prefix="admin"} 0
envoy_http_downstream_rq_xx{envoy_response_code_class="2",envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_runtime_load_success counter
envoy_runtime_load_success{} 1
# TYPE envoy_http_downstream_cx_destroy_local counter
envoy_http_downstream_cx_destroy_local{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_listener_no_filter_chain_match counter
envoy_listener_no_filter_chain_match{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_worker_0_downstream_cx_total counter
envoy_listener_worker_0_downstream_cx_total{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_downstream_cx_destroy counter
envoy_listener_downstream_cx_destroy{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_downstream_pre_cx_timeout counter
envoy_listener_downstream_pre_cx_timeout{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_worker_1_downstream_cx_total counter
envoy_listener_worker_1_downstream_cx_total{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_downstream_cx_total counter
envoy_listener_downstream_cx_total{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_manager_listener_added counter
envoy_listener_manager_listener_added{} 1
# TYPE envoy_listener_manager_listener_create_failure counter
envoy_listener_manager_listener_create_failure{} 0
# TYPE envoy_listener_manager_listener_modified counter
envoy_listener_manager_listener_modified{} 0
# TYPE envoy_listener_manager_listener_create_success counter
envoy_listener_manager_listener_create_success{} 2
# TYPE envoy_listener_manager_listener_removed counter
envoy_listener_manager_listener_removed{} 0
# TYPE envoy_listener_manager_listener_stopped counter
envoy_listener_manager_listener_stopped{} 0
# TYPE envoy_listener_admin_http_downstream_rq_xx counter
envoy_listener_admin_http_downstream_rq_xx{envoy_response_code_class="2",envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_listener_admin_downstream_cx_destroy counter
envoy_listener_admin_downstream_cx_destroy{} 4079
# TYPE envoy_listener_admin_http_downstream_rq_completed counter
envoy_listener_admin_http_downstream_rq_completed{envoy_http_conn_manager_prefix="admin"} 4079
envoy_listener_admin_http_downstream_rq_xx{envoy_response_code_class="3",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_listener_admin_downstream_pre_cx_timeout counter
envoy_listener_admin_downstream_pre_cx_timeout{} 0
envoy_listener_admin_http_downstream_rq_xx{envoy_response_code_class="5",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_listener_admin_downstream_cx_total counter
envoy_listener_admin_downstream_cx_total{} 4080
# TYPE envoy_listener_admin_no_filter_chain_match counter
envoy_listener_admin_no_filter_chain_match{} 0
# TYPE envoy_listener_admin_main_thread_downstream_cx_total counter
envoy_listener_admin_main_thread_downstream_cx_total{} 4080
envoy_listener_admin_http_downstream_rq_xx{envoy_response_code_class="4",envoy_http_conn_manager_prefix="admin"} 0
envoy_listener_admin_http_downstream_rq_xx{envoy_response_code_class="1",envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_tcp_downstream_cx_total counter
envoy_tcp_downstream_cx_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_cx_tx_bytes_total counter
envoy_tcp_downstream_cx_tx_bytes_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_cx_rx_bytes_total counter
envoy_tcp_downstream_cx_rx_bytes_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_cx_no_route counter
envoy_tcp_downstream_cx_no_route{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_upstream_flush_total counter
envoy_tcp_upstream_flush_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_flow_control_paused_reading_total counter
envoy_tcp_downstream_flow_control_paused_reading_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_flow_control_resumed_reading_total counter
envoy_tcp_downstream_flow_control_resumed_reading_total{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_idle_timeout counter
envoy_tcp_idle_timeout{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_cluster_upstream_rq_tx_reset counter
envoy_cluster_upstream_rq_tx_reset{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy_with_active_rq counter
envoy_cluster_upstream_cx_destroy_with_active_rq{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_pool_overflow counter
envoy_cluster_upstream_cx_pool_overflow{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_rx_bytes_total counter
envoy_cluster_upstream_cx_rx_bytes_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_update_failure counter
envoy_cluster_update_failure{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy_remote counter
envoy_cluster_upstream_cx_destroy_remote{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_cluster_too_small counter
envoy_cluster_lb_zone_cluster_too_small{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_recalculate_zone_structures counter
envoy_cluster_lb_recalculate_zone_structures{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_overflow counter
envoy_cluster_upstream_cx_overflow{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_flow_control_drained_total counter
envoy_cluster_upstream_flow_control_drained_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_maintenance_mode counter
envoy_cluster_upstream_rq_maintenance_mode{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_routing_all_directly counter
envoy_cluster_lb_zone_routing_all_directly{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_subsets_selected counter
envoy_cluster_lb_subsets_selected{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_failure counter
envoy_cluster_health_check_failure{envoy_cluster_name="backend2015"} 2048
# TYPE envoy_cluster_lb_subsets_created counter
envoy_cluster_lb_subsets_created{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_retry_or_shadow_abandoned counter
envoy_cluster_retry_or_shadow_abandoned{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_per_try_timeout counter
envoy_cluster_upstream_rq_per_try_timeout{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_success counter
envoy_cluster_health_check_success{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_passive_failure counter
envoy_cluster_health_check_passive_failure{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_completed counter
envoy_cluster_upstream_rq_completed{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_number_differs counter
envoy_cluster_lb_zone_number_differs{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_update_no_rebuild counter
envoy_cluster_update_no_rebuild{envoy_cluster_name="backend2015"} 2251
# TYPE envoy_cluster_upstream_cx_http2_total counter
envoy_cluster_upstream_cx_http2_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_subsets_fallback_panic counter
envoy_cluster_lb_subsets_fallback_panic{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_total counter
envoy_cluster_upstream_cx_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_timeout counter
envoy_cluster_upstream_rq_timeout{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_internal_redirect_succeeded_total counter
envoy_cluster_upstream_internal_redirect_succeeded_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_close_notify counter
envoy_cluster_upstream_cx_close_notify{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_flow_control_resumed_reading_total counter
envoy_cluster_upstream_flow_control_resumed_reading_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_assignment_timeout_received counter
envoy_cluster_assignment_timeout_received{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_pending_total counter
envoy_cluster_upstream_rq_pending_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_routing_cross_zone counter
envoy_cluster_lb_zone_routing_cross_zone{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_internal_redirect_failed_total counter
envoy_cluster_upstream_internal_redirect_failed_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy counter
envoy_cluster_upstream_cx_destroy{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_local_cluster_not_ok counter
envoy_cluster_lb_local_cluster_not_ok{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_attempt counter
envoy_cluster_health_check_attempt{envoy_cluster_name="backend2015"} 2048
# TYPE envoy_cluster_upstream_cx_none_healthy counter
envoy_cluster_upstream_cx_none_healthy{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_no_capacity_left counter
envoy_cluster_lb_zone_no_capacity_left{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_flow_control_backed_up_total counter
envoy_cluster_upstream_flow_control_backed_up_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_subsets_removed counter
envoy_cluster_lb_subsets_removed{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_pending_overflow counter
envoy_cluster_upstream_rq_pending_overflow{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_zone_routing_sampled counter
envoy_cluster_lb_zone_routing_sampled{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_network_failure counter
envoy_cluster_health_check_network_failure{envoy_cluster_name="backend2015"} 2048
# TYPE envoy_cluster_membership_change counter
envoy_cluster_membership_change{envoy_cluster_name="backend2015"} 1
# TYPE envoy_cluster_original_dst_host_invalid counter
envoy_cluster_original_dst_host_invalid{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_idle_timeout counter
envoy_cluster_upstream_cx_idle_timeout{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_total counter
envoy_cluster_upstream_rq_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy_remote_with_active_rq counter
envoy_cluster_upstream_cx_destroy_remote_with_active_rq{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_pending_failure_eject counter
envoy_cluster_upstream_rq_pending_failure_eject{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_bind_errors counter
envoy_cluster_bind_errors{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_update_success counter
envoy_cluster_update_success{envoy_cluster_name="backend2015"} 2252
# TYPE envoy_cluster_upstream_cx_connect_timeout counter
envoy_cluster_upstream_cx_connect_timeout{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_tx_bytes_total counter
envoy_cluster_upstream_cx_tx_bytes_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_update_empty counter
envoy_cluster_update_empty{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_protocol_error counter
envoy_cluster_upstream_cx_protocol_error{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_update_attempt counter
envoy_cluster_update_attempt{envoy_cluster_name="backend2015"} 2252
# TYPE envoy_cluster_upstream_rq_rx_reset counter
envoy_cluster_upstream_rq_rx_reset{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy_local_with_active_rq counter
envoy_cluster_upstream_cx_destroy_local_with_active_rq{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_http1_total counter
envoy_cluster_upstream_cx_http1_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_cancelled counter
envoy_cluster_upstream_rq_cancelled{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_destroy_local counter
envoy_cluster_upstream_cx_destroy_local{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_retry_overflow counter
envoy_cluster_upstream_rq_retry_overflow{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_connect_attempts_exceeded counter
envoy_cluster_upstream_cx_connect_attempts_exceeded{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_assignment_stale counter
envoy_cluster_assignment_stale{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_connect_fail counter
envoy_cluster_upstream_cx_connect_fail{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_retry counter
envoy_cluster_upstream_rq_retry{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_verify_cluster counter
envoy_cluster_health_check_verify_cluster{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_retry_success counter
envoy_cluster_upstream_rq_retry_success{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_subsets_fallback counter
envoy_cluster_lb_subsets_fallback{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_max_requests counter
envoy_cluster_upstream_cx_max_requests{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_flow_control_paused_reading_total counter
envoy_cluster_upstream_flow_control_paused_reading_total{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_default_total_match_count counter
envoy_cluster_default_total_match_count{envoy_cluster_name="backend2015"} 2252
# TYPE envoy_cluster_lb_healthy_panic counter
envoy_cluster_lb_healthy_panic{envoy_cluster_name="backend2015"} 0
# TYPE envoy_server_parent_connections gauge
envoy_server_parent_connections{} 0
# TYPE envoy_http_downstream_cx_http1_active gauge
envoy_http_downstream_cx_http1_active{envoy_http_conn_manager_prefix="admin"} 1
# TYPE envoy_cluster_manager_warming_clusters gauge
envoy_cluster_manager_warming_clusters{} 0
# TYPE envoy_server_days_until_first_cert_expiring gauge
envoy_server_days_until_first_cert_expiring{} 2147483647
# TYPE envoy_filesystem_write_total_buffered gauge
envoy_filesystem_write_total_buffered{} 251
# TYPE envoy_server_stats_recent_lookups gauge
envoy_server_stats_recent_lookups{} 0
# TYPE envoy_http_downstream_cx_active gauge
envoy_http_downstream_cx_active{envoy_http_conn_manager_prefix="admin"} 1
# TYPE envoy_server_memory_allocated gauge
envoy_server_memory_allocated{} 3818776
# TYPE envoy_server_state gauge
envoy_server_state{} 0
# TYPE envoy_server_memory_heap_size gauge
envoy_server_memory_heap_size{} 5242880
# TYPE envoy_http_downstream_cx_http2_active gauge
envoy_http_downstream_cx_http2_active{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_server_concurrency gauge
envoy_server_concurrency{} 2
# TYPE envoy_server_version gauge
envoy_server_version{} 11219146
# TYPE envoy_http_downstream_cx_http3_active gauge
envoy_http_downstream_cx_http3_active{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_server_live gauge
envoy_server_live{} 1
# TYPE envoy_http_downstream_cx_rx_bytes_buffered gauge
envoy_http_downstream_cx_rx_bytes_buffered{envoy_http_conn_manager_prefix="admin"} 95
# TYPE envoy_http_downstream_cx_ssl_active gauge
envoy_http_downstream_cx_ssl_active{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_server_uptime gauge
envoy_server_uptime{} 11258
# TYPE envoy_server_total_connections gauge
envoy_server_total_connections{} 0
# TYPE envoy_http_downstream_cx_tx_bytes_buffered gauge
envoy_http_downstream_cx_tx_bytes_buffered{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_cx_upgrades_active gauge
envoy_http_downstream_cx_upgrades_active{envoy_http_conn_manager_prefix="admin"} 0
# TYPE envoy_http_downstream_rq_active gauge
envoy_http_downstream_rq_active{envoy_http_conn_manager_prefix="admin"} 1
# TYPE envoy_server_hot_restart_epoch gauge
envoy_server_hot_restart_epoch{} 0
# TYPE envoy_runtime_num_keys gauge
envoy_runtime_num_keys{} 0
# TYPE envoy_runtime_admin_overrides_active gauge
envoy_runtime_admin_overrides_active{} 0
# TYPE envoy_runtime_num_layers gauge
envoy_runtime_num_layers{} 2
# TYPE envoy_cluster_manager_active_clusters gauge
envoy_cluster_manager_active_clusters{} 1
# TYPE envoy_listener_downstream_pre_cx_active gauge
envoy_listener_downstream_pre_cx_active{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_worker_1_downstream_cx_active gauge
envoy_listener_worker_1_downstream_cx_active{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_downstream_cx_active gauge
envoy_listener_downstream_cx_active{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_worker_0_downstream_cx_active gauge
envoy_listener_worker_0_downstream_cx_active{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_manager_total_listeners_active gauge
envoy_listener_manager_total_listeners_active{} 1
# TYPE envoy_listener_manager_total_listeners_draining gauge
envoy_listener_manager_total_listeners_draining{} 0
# TYPE envoy_listener_manager_total_listeners_warming gauge
envoy_listener_manager_total_listeners_warming{} 0
# TYPE envoy_listener_admin_downstream_pre_cx_active gauge
envoy_listener_admin_downstream_pre_cx_active{} 0
# TYPE envoy_listener_admin_main_thread_downstream_cx_active gauge
envoy_listener_admin_main_thread_downstream_cx_active{} 1
# TYPE envoy_listener_admin_downstream_cx_active gauge
envoy_listener_admin_downstream_cx_active{} 1
# TYPE envoy_tcp_downstream_cx_tx_bytes_buffered gauge
envoy_tcp_downstream_cx_tx_bytes_buffered{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_upstream_flush_active gauge
envoy_tcp_upstream_flush_active{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_tcp_downstream_cx_rx_bytes_buffered gauge
envoy_tcp_downstream_cx_rx_bytes_buffered{envoy_tcp_prefix="ingress_tcp"} 0
# TYPE envoy_cluster_health_check_degraded gauge
envoy_cluster_health_check_degraded{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_default_rq_pending_open gauge
envoy_cluster_circuit_breakers_default_rq_pending_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_max_host_weight gauge
envoy_cluster_max_host_weight{envoy_cluster_name="backend2015"} 1
# TYPE envoy_cluster_circuit_breakers_default_rq_retry_open gauge
envoy_cluster_circuit_breakers_default_rq_retry_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_high_cx_open gauge
envoy_cluster_circuit_breakers_high_cx_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_rx_bytes_buffered gauge
envoy_cluster_upstream_cx_rx_bytes_buffered{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_rq_active gauge
envoy_cluster_upstream_rq_active{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_high_rq_open gauge
envoy_cluster_circuit_breakers_high_rq_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_default_cx_pool_open gauge
envoy_cluster_circuit_breakers_default_cx_pool_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_high_rq_pending_open gauge
envoy_cluster_circuit_breakers_high_rq_pending_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_default_cx_open gauge
envoy_cluster_circuit_breakers_default_cx_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_lb_subsets_active gauge
envoy_cluster_lb_subsets_active{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_membership_healthy gauge
envoy_cluster_membership_healthy{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_default_rq_open gauge
envoy_cluster_circuit_breakers_default_rq_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_circuit_breakers_high_rq_retry_open gauge
envoy_cluster_circuit_breakers_high_rq_retry_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_health_check_healthy gauge
envoy_cluster_health_check_healthy{envoy_cluster_name="backend2015"} 1
# TYPE envoy_cluster_membership_degraded gauge
envoy_cluster_membership_degraded{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_membership_total gauge
envoy_cluster_membership_total{envoy_cluster_name="backend2015"} 1
# TYPE envoy_cluster_upstream_rq_pending_active gauge
envoy_cluster_upstream_rq_pending_active{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_version gauge
envoy_cluster_version{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_active gauge
envoy_cluster_upstream_cx_active{envoy_cluster_name="backend2015"} 50
# TYPE envoy_cluster_circuit_breakers_high_cx_pool_open gauge
envoy_cluster_circuit_breakers_high_cx_pool_open{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_tx_bytes_buffered gauge
envoy_cluster_upstream_cx_tx_bytes_buffered{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_membership_excluded gauge
envoy_cluster_membership_excluded{envoy_cluster_name="backend2015"} 0
# TYPE envoy_server_initialization_time_ms histogram
envoy_server_initialization_time_ms_bucket{le="0.5"} 0
envoy_server_initialization_time_ms_bucket{le="1"} 0
envoy_server_initialization_time_ms_bucket{le="5"} 0
envoy_server_initialization_time_ms_bucket{le="10"} 0
envoy_server_initialization_time_ms_bucket{le="25"} 1
envoy_server_initialization_time_ms_bucket{le="50"} 1
envoy_server_initialization_time_ms_bucket{le="100"} 1
envoy_server_initialization_time_ms_bucket{le="250"} 1
envoy_server_initialization_time_ms_bucket{le="500"} 1
envoy_server_initialization_time_ms_bucket{le="1000"} 1
envoy_server_initialization_time_ms_bucket{le="2500"} 1
envoy_server_initialization_time_ms_bucket{le="5000"} 1
envoy_server_initialization_time_ms_bucket{le="10000"} 1
envoy_server_initialization_time_ms_bucket{le="30000"} 1
envoy_server_initialization_time_ms_bucket{le="60000"} 1
envoy_server_initialization_time_ms_bucket{le="300000"} 1
envoy_server_initialization_time_ms_bucket{le="600000"} 1
envoy_server_initialization_time_ms_bucket{le="1800000"} 1
envoy_server_initialization_time_ms_bucket{le="3600000"} 1
envoy_server_initialization_time_ms_bucket{le="+Inf"} 1
envoy_server_initialization_time_ms_sum{} 15.5
envoy_server_initialization_time_ms_count{} 1
# TYPE envoy_http_downstream_rq_time histogram
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="0.5"} 1715
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="1"} 1715
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="5"} 4036
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="10"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="25"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="50"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="100"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="250"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="500"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="1000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="2500"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="5000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="10000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="30000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="60000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="300000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="600000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="1800000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="3600000"} 4079
envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="admin",le="+Inf"} 4079
envoy_http_downstream_rq_time_sum{envoy_http_conn_manager_prefix="admin"} 3256.2000000000002728484105318785
envoy_http_downstream_rq_time_count{envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_http_downstream_cx_length_ms histogram
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="0.5"} 1177
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="1"} 1177
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="5"} 3852
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="10"} 4074
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="25"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="50"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="100"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="250"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="500"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="1000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="2500"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="5000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="10000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="30000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="60000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="300000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="600000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="1800000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="3600000"} 4079
envoy_http_downstream_cx_length_ms_bucket{envoy_http_conn_manager_prefix="admin",le="+Inf"} 4079
envoy_http_downstream_cx_length_ms_sum{envoy_http_conn_manager_prefix="admin"} 6363.3500000000003637978807091713
envoy_http_downstream_cx_length_ms_count{envoy_http_conn_manager_prefix="admin"} 4079
# TYPE envoy_listener_downstream_cx_length_ms histogram
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="0.5"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="1"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="5"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="10"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="25"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="50"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="100"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="250"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="500"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="1000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="2500"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="5000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="10000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="30000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="60000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="300000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="600000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="1800000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="3600000"} 0
envoy_listener_downstream_cx_length_ms_bucket{envoy_listener_address="0.0.0.0_2015",le="+Inf"} 0
envoy_listener_downstream_cx_length_ms_sum{envoy_listener_address="0.0.0.0_2015"} 0
envoy_listener_downstream_cx_length_ms_count{envoy_listener_address="0.0.0.0_2015"} 0
# TYPE envoy_listener_admin_downstream_cx_length_ms histogram
envoy_listener_admin_downstream_cx_length_ms_bucket{le="0.5"} 1177
envoy_listener_admin_downstream_cx_length_ms_bucket{le="1"} 1177
envoy_listener_admin_downstream_cx_length_ms_bucket{le="5"} 3851
envoy_listener_admin_downstream_cx_length_ms_bucket{le="10"} 4074
envoy_listener_admin_downstream_cx_length_ms_bucket{le="25"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="50"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="100"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="250"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="500"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="1000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="2500"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="5000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="10000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="30000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="60000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="300000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="600000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="1800000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="3600000"} 4079
envoy_listener_admin_downstream_cx_length_ms_bucket{le="+Inf"} 4079
envoy_listener_admin_downstream_cx_length_ms_sum{} 6359.3499999999985448084771633148
envoy_listener_admin_downstream_cx_length_ms_count{} 4079
# TYPE envoy_cluster_upstream_cx_connect_ms histogram
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="0.5"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="1"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="5"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="10"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="25"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="50"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="100"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="250"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="500"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="1000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="2500"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="5000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="10000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="30000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="60000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="300000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="600000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="1800000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="3600000"} 0
envoy_cluster_upstream_cx_connect_ms_bucket{envoy_cluster_name="backend2015",le="+Inf"} 0
envoy_cluster_upstream_cx_connect_ms_sum{envoy_cluster_name="backend2015"} 0
envoy_cluster_upstream_cx_connect_ms_count{envoy_cluster_name="backend2015"} 0
# TYPE envoy_cluster_upstream_cx_length_ms histogram
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="0.5"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="1"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="5"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="10"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="25"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="50"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="100"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="250"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="500"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="1000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="2500"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="5000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="10000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="30000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="60000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="300000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="600000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="1800000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="3600000"} 0
envoy_cluster_upstream_cx_length_ms_bucket{envoy_cluster_name="backend2015",le="+Inf"} 0
envoy_cluster_upstream_cx_length_ms_sum{envoy_cluster_name="backend2015"} 0
envoy_cluster_upstream_cx_length_ms_count{envoy_cluster_name="backend2015"} 0
`
