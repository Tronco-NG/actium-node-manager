
with identities as (
  select organization_id, terminal_id from telemetry.terminal_location_current
  union
  select organization_id, terminal_id from telemetry.terminal_presence_current
  union
  select organization_id, terminal_id from telemetry.gps_batches
  union
  select organization_id, terminal_id from telemetry.gps_points
),
terminal_raw as (
  select
    i.organization_id,
    i.terminal_id as observed_terminal_id,
    coalesce(
      nullif(p.metadata->>'assignedDeviceId', ''),
      nullif(p.metadata->>'assigned_device_id', ''),
      nullif(l.metadata->>'assignedDeviceId', ''),
      nullif(l.metadata->>'assigned_device_id', ''),
      nullif(lp.metadata->>'assignedDeviceId', ''),
      nullif(lp.metadata->>'assigned_device_id', ''),
      nullif(p.metadata->>'terminalUuid', ''),
      nullif(p.metadata->>'terminal_uuid', ''),
      nullif(l.metadata->>'terminalUuid', ''),
      nullif(l.metadata->>'terminal_uuid', ''),
      nullif(lp.metadata->>'terminalUuid', ''),
      nullif(lp.metadata->>'terminal_uuid', ''),
      i.terminal_id
    ) as canonical_terminal_id,
    l.binding_epoch,
    l.sequence,
    l.fix_at,
    l.ingested_at,
    l.projected_at,
    l.latitude,
    l.longitude,
    l.accuracy,
    l.speed,
    l.heading,
    l.continuity_status,
    l.queue_lag_seconds,
    p.heartbeat_at,
    p.status as presence_status,
    p.app_state,
    p.battery_level,
    p.queue_depth,
    coalesce(
      nullif(p.metadata->>'terminalLabel', ''),
      nullif(p.metadata->>'terminal_label', ''),
      nullif(p.metadata->>'terminalName', ''),
      nullif(p.metadata->>'terminal_name', ''),
      nullif(p.metadata->>'deviceName', ''),
      nullif(p.metadata->>'device_name', ''),
      nullif(l.metadata->>'terminalLabel', ''),
      nullif(l.metadata->>'terminal_label', ''),
      nullif(l.metadata->>'terminalName', ''),
      nullif(l.metadata->>'terminal_name', ''),
      nullif(l.metadata->>'deviceName', ''),
      nullif(l.metadata->>'device_name', ''),
      nullif(lp.metadata->>'terminalLabel', ''),
      nullif(lp.metadata->>'terminal_label', ''),
      nullif(lp.metadata->>'terminalName', ''),
      nullif(lp.metadata->>'terminal_name', ''),
      nullif(lp.metadata->>'deviceName', ''),
      nullif(lp.metadata->>'device_name', '')
    ) as terminal_label,
    lower(coalesce(
      nullif(p.metadata->>'platform', ''),
      nullif(l.metadata->>'platform', ''),
      nullif(lp.metadata->>'platform', '')
    )) as terminal_platform,
    lower(coalesce(
      nullif(p.metadata->>'source', ''),
      nullif(l.metadata->>'source', ''),
      nullif(lp.metadata->>'source', '')
    )) as terminal_source,
    lower(coalesce(
      nullif(p.metadata->>'runtime', ''),
      nullif(p.metadata->>'clientRuntime', ''),
      nullif(p.metadata->>'client_runtime', ''),
      nullif(l.metadata->>'runtime', ''),
      nullif(l.metadata->>'clientRuntime', ''),
      nullif(l.metadata->>'client_runtime', ''),
      nullif(lp.metadata->>'runtime', ''),
      nullif(lp.metadata->>'clientRuntime', ''),
      nullif(lp.metadata->>'client_runtime', '')
    )) as terminal_runtime,
    lower(coalesce(
      nullif(p.metadata->>'deviceType', ''),
      nullif(p.metadata->>'device_type', ''),
      nullif(p.metadata->>'terminalDeviceType', ''),
      nullif(p.metadata->>'terminal_device_type', ''),
      nullif(l.metadata->>'deviceType', ''),
      nullif(l.metadata->>'device_type', ''),
      nullif(l.metadata->>'terminalDeviceType', ''),
      nullif(l.metadata->>'terminal_device_type', ''),
      nullif(lp.metadata->>'deviceType', ''),
      nullif(lp.metadata->>'device_type', ''),
      nullif(lp.metadata->>'terminalDeviceType', ''),
      nullif(lp.metadata->>'terminal_device_type', '')
    )) as terminal_device_type,
    lower(coalesce(
      nullif(p.metadata->>'terminalType', ''),
      nullif(p.metadata->>'terminal_type', ''),
      nullif(l.metadata->>'terminalType', ''),
      nullif(l.metadata->>'terminal_type', ''),
      nullif(lp.metadata->>'terminalType', ''),
      nullif(lp.metadata->>'terminal_type', '')
    )) as terminal_type,
    case lower(coalesce(
      nullif(p.metadata->>'isNative', ''),
      nullif(p.metadata->>'is_native', ''),
      nullif(l.metadata->>'isNative', ''),
      nullif(l.metadata->>'is_native', ''),
      nullif(lp.metadata->>'isNative', ''),
      nullif(lp.metadata->>'is_native', '')
    ))
      when 'true' then true
      when 'false' then false
      else null
    end as terminal_is_native,
    b.batch_id,
    b.received_at as batch_received_at,
    b.processed_at as batch_processed_at,
    b.status as batch_status,
    b.error_code as batch_error_code,
    b.point_count as batch_point_count,
    d.dvr_first_point_at,
    d.dvr_last_point_at,
    d.dvr_points_24h,
    d.dvr_session_id
  from identities i
  left join telemetry.terminal_location_current l
    on l.organization_id = i.organization_id and l.terminal_id = i.terminal_id
  left join telemetry.terminal_presence_current p
    on p.organization_id = i.organization_id and p.terminal_id = i.terminal_id
  left join lateral (
    select batch_id, received_at, processed_at, status, error_code, point_count
    from telemetry.gps_batches
    where organization_id = i.organization_id and terminal_id = i.terminal_id
    order by received_at desc
    limit 1
  ) b on true
  left join lateral (
    select metadata
    from telemetry.gps_points
    where organization_id = i.organization_id and terminal_id = i.terminal_id
    order by ingested_at desc, fix_at desc
    limit 1
  ) lp on true
  left join lateral (
    select
      min(fix_at) filter (where fix_at >= clock_timestamp() - interval '24 hours') as dvr_first_point_at,
      max(fix_at) filter (where fix_at >= clock_timestamp() - interval '24 hours') as dvr_last_point_at,
      count(*) filter (where fix_at >= clock_timestamp() - interval '24 hours')::bigint as dvr_points_24h,
      (array_agg(coalesce(metadata->>'dvrSessionId', metadata->>'dvr_session_id')
        order by fix_at desc) filter (
          where coalesce(metadata->>'dvrSessionId', metadata->>'dvr_session_id') is not null
        ))[1] as dvr_session_id
    from telemetry.gps_points
    where organization_id = i.organization_id and terminal_id = i.terminal_id
      and fix_at >= clock_timestamp() - interval '24 hours'
  ) d on true
),
terminal_consolidated as (
  select
    terminal_raw.*,
    max(terminal_label) over identity as canonical_terminal_label,
    max(terminal_platform) over identity as canonical_terminal_platform,
    max(terminal_runtime) over identity as canonical_terminal_runtime,
    max(terminal_device_type) over identity as canonical_terminal_device_type,
    max(terminal_type) over identity as canonical_terminal_type,
    bool_or(terminal_is_native) over identity as canonical_terminal_is_native,
    bool_or(
      terminal_source like 'native_%'
      or terminal_source in ('background_geolocation', 'capacitor')
    ) over identity as canonical_native_source,
    min(dvr_first_point_at) over identity as canonical_dvr_first_point_at,
    max(dvr_last_point_at) over identity as canonical_dvr_last_point_at,
    sum(coalesce(dvr_points_24h, 0)) over identity as canonical_dvr_points_24h,
    max(dvr_session_id) over identity as canonical_dvr_session_id,
    row_number() over (
      partition by organization_id, canonical_terminal_id
      order by coalesce(fix_at, heartbeat_at, batch_received_at) desc nulls last,
        observed_terminal_id
    ) as terminal_rank
  from terminal_raw
  window identity as (partition by organization_id, canonical_terminal_id)
),
terminal_audit as (
  select
    terminal_consolidated.*,
    case
      when canonical_terminal_platform in ('android', 'ios')
        then 'capacitor_mobile'
      when canonical_terminal_runtime = 'capacitor'
        and coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'mobile', 'mobile_terminal', 'handheld', 'android_terminal'
        )
        then 'capacitor_mobile'
      when (
          canonical_terminal_is_native is true
          or canonical_native_source is true
        )
        and coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'mobile', 'mobile_terminal', 'handheld', 'android_terminal'
        )
        then 'capacitor_mobile'
      when canonical_terminal_platform in ('web', 'windows', 'linux', 'macos')
        or canonical_terminal_runtime in ('web', 'tauri')
        or coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'fixed', 'fijo', 'static', 'pc', 'web_station'
        )
        then 'non_mobile'
      else 'unknown'
    end as terminal_class
  from terminal_consolidated
  where terminal_rank = 1
)
select jsonb_build_object(
  'terminals',
  coalesce((
    select jsonb_agg(jsonb_build_object(
      'organizationId', organization_id,
      'terminalId', canonical_terminal_id,
      'bindingEpoch', binding_epoch,
      'sequence', sequence,
      'fixAt', fix_at,
      'ingestedAt', ingested_at,
      'projectedAt', projected_at,
      'latitude', latitude,
      'longitude', longitude,
      'accuracy', accuracy,
      'speed', speed,
      'heading', heading,
      'continuityStatus', continuity_status,
      'queueLagSeconds', queue_lag_seconds,
      'heartbeatAt', heartbeat_at,
      'presenceStatus', presence_status,
      'appState', app_state,
      'batteryLevel', battery_level,
      'queueDepth', queue_depth,
      'terminalLabel', canonical_terminal_label,
      'terminalPlatform', canonical_terminal_platform,
      'terminalRuntime', canonical_terminal_runtime,
      'terminalDeviceType', canonical_terminal_device_type,
      'terminalType', canonical_terminal_type,
      'terminalIsNative', canonical_terminal_is_native,
      'terminalClass', terminal_class,
      'lastBatchId', batch_id,
      'lastBatchReceivedAt', batch_received_at,
      'lastBatchProcessedAt', batch_processed_at,
      'lastBatchStatus', batch_status,
      'lastBatchErrorCode', batch_error_code,
      'lastBatchPointCount', batch_point_count,
      'dvrFirstPointAt', canonical_dvr_first_point_at,
      'dvrLastPointAt', canonical_dvr_last_point_at,
      'dvrPoints24h', coalesce(canonical_dvr_points_24h, 0),
      'dvrSessionId', canonical_dvr_session_id,
      'recentBatches', coalesce((
        select jsonb_agg(jsonb_build_object(
          'batchId', recent.batch_id,
          'receivedAt', recent.received_at,
          'processedAt', recent.processed_at,
          'status', recent.status,
          'errorCode', recent.error_code,
          'pointCount', recent.point_count,
          'firstSequence', recent.first_sequence
        ) order by recent.received_at desc)
        from (
          select
            rb.batch_id,
            rb.received_at,
            rb.processed_at,
            rb.status,
            rb.error_code,
            rb.point_count,
            rb.first_sequence
          from telemetry.gps_batches rb
          where rb.organization_id = terminal_audit.organization_id
            and rb.terminal_id in (
              terminal_audit.observed_terminal_id,
              terminal_audit.canonical_terminal_id
            )
          order by rb.received_at desc
          limit 8
        ) recent
      ), '[]'::jsonb),
      'recentPoints', coalesce((
        select jsonb_agg(jsonb_build_object(
          'sequence', recent.sequence,
          'fixAt', recent.fix_at,
          'ingestedAt', recent.ingested_at,
          'source', recent.metadata->>'source',
          'appState', recent.app_state,
          'provider', recent.provider,
          'accuracy', recent.accuracy,
          'latitude', recent.latitude,
          'longitude', recent.longitude,
          'dvrSessionId', coalesce(
            recent.metadata->>'dvrSessionId',
            recent.metadata->>'dvr_session_id'
          )
        ) order by recent.ingested_at desc, recent.fix_at desc)
        from (
          select
            rp.sequence,
            rp.fix_at,
            rp.ingested_at,
            rp.metadata,
            rp.app_state,
            rp.provider,
            rp.accuracy,
            rp.latitude,
            rp.longitude
          from telemetry.gps_points rp
          where rp.organization_id = terminal_audit.organization_id
            and (
              rp.terminal_id in (
                terminal_audit.observed_terminal_id,
                terminal_audit.canonical_terminal_id
              )
              or coalesce(
                nullif(rp.metadata->>'assignedDeviceId', ''),
                nullif(rp.metadata->>'assigned_device_id', ''),
                nullif(rp.metadata->>'terminalUuid', ''),
                nullif(rp.metadata->>'terminal_uuid', '')
              ) = terminal_audit.canonical_terminal_id
            )
          order by rp.ingested_at desc, rp.fix_at desc
          limit 12
        ) recent
      ), '[]'::jsonb)
    ) order by coalesce(fix_at, heartbeat_at, batch_received_at) desc nulls last)
    from terminal_audit
  ), '[]'::jsonb),
  'unresolvedDeadLetters', (
    select count(*) from telemetry.dead_letters where resolved_at is null
  ),
  'recentDeadLetters', coalesce((
    select jsonb_agg(jsonb_build_object(
      'stream', stream,
      'subject', subject,
      'category', category,
      'reason', reason,
      'failedAt', failed_at
    ) order by failed_at desc)
    from (
      select stream, subject, category, reason, failed_at
      from telemetry.dead_letters
      where resolved_at is null
      order by failed_at desc
      limit 20
    ) latest_dead_letters
  ), '[]'::jsonb)
);
