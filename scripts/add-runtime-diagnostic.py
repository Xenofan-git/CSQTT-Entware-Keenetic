from pathlib import Path

tun = Path("csqtt-current/rust-client/tun.rs")
s = tun.read_text()
old = '                                    let file = unsafe { File::from_raw_fd(descriptor) };\n                                    configure_nonblocking(file.as_raw_fd())?;'
new = '''                                    let file = unsafe { File::from_raw_fd(descriptor) };
                                    let kind = match file.metadata() {
                                        Ok(meta) => {
                                            use std::os::unix::fs::FileTypeExt;
                                            let ty = meta.file_type();
                                            if ty.is_char_device() {
                                                "char-device"
                                            } else if ty.is_socket() {
                                                "socket"
                                            } else if ty.is_file() {
                                                "regular-file"
                                            } else {
                                                "other"
                                            }
                                        }
                                        Err(_) => "metadata-error",
                                    };
                                    eprintln!("[TUN FD] received fd={} kind={}", file.as_raw_fd(), kind);
                                    configure_nonblocking(file.as_raw_fd())?;'''
if old not in s: raise SystemExit("tun FD anchor not found")
tun.write_text(s.replace(old, new, 1))

p = Path("csqtt-current/rust-client/dispatcher.rs")
s = p.read_text()
old = '''    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        let Some(ticket) = client_perf::measure_sampled(PerfStage::Scheduler, 64, || {'''
new = '''    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        crate::log_error!("[PATH DEBUG] dispatch len={} first={:02x?}", packet.len(), &packet.as_slice()[..packet.len().min(20)]);
        let Some(ticket) = client_perf::measure_sampled(PerfStage::Scheduler, 64, || {'''
if old not in s: raise SystemExit("dispatch anchor not found")
s=s.replace(old,new,1)
old='''        if let Err(packet) = enqueue_selected_worker(workers, ticket, packet) {
            let _ = replace_oldest_in_selected_queue(workers, ticket, packet);
        }'''
new='''        match enqueue_selected_worker(workers, ticket, packet) {
            Ok(()) => crate::log_error!("[PATH DEBUG] queued worker={} class={:?}", ticket.start_slot, ticket.class),
            Err(packet) => {
                crate::log_error!("[PATH DEBUG] queue FULL/CLOSED worker={} class={:?} len={}", ticket.start_slot, ticket.class, packet.len());
                let _ = replace_oldest_in_selected_queue(workers, ticket, packet);
            }
        }'''
if old not in s: raise SystemExit("enqueue anchor not found")
s=s.replace(old,new,1)
old='''                let state = {
                    let (packet, written) = pending.as_mut().expect("TUN packet is pending");
                    self.try_write_tun_packet(&mut guard, &stats, packet, written)
                };'''
new='''                let state = {
                    let (packet, written) = pending.as_mut().expect("TUN packet is pending");
                    if *written == 0 {
                        crate::log_error!("[PATH DEBUG] write_tun len={} first={:02x?}", packet.len(), &packet.as_slice()[..packet.len().min(32)]);
                    }
                    self.try_write_tun_packet(&mut guard, &stats, packet, written)
                };'''
if old not in s: raise SystemExit("write call anchor not found")
s=s.replace(old,new,1)
old='''            Ok(Err(error)) => {
                crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
                TunWriteState::Failed
            }'''
new='''            Ok(Err(error)) => {
                crate::log_error!("[PATH DEBUG] write_tun ERROR len={} written={} errno={:?} first={:02x?}", packet.len(), *written, error.raw_os_error(), &packet.as_slice()[..packet.len().min(32)]);
                crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
                TunWriteState::Failed
            }'''
if old not in s: raise SystemExit("write error anchor not found")
s=s.replace(old,new,1)
p.write_text(s)

sess=Path("csqtt-current/rust-client/session.rs")
s=sess.read_text()
old='''    transport.flush_queued_data().await?;
    Ok(sent)
}'''
new='''    transport.flush_queued_data().await?;
    crate::log_error!("[PATH DEBUG] writer sent={} first_class={:?}", sent, first.class);
    Ok(sent)
}'''
if old not in s: raise SystemExit("writer anchor not found")
s=s.replace(old,new,1)
old='''        deliver_inbound_packet(&dispatcher, packet);'''
new='''        crate::log_error!("[PATH DEBUG] inbound len={} first={:02x?}", packet.len(), &packet.as_slice()[..packet.len().min(32)]);
        deliver_inbound_packet(&dispatcher, packet);'''
if old not in s: raise SystemExit("inbound anchor not found")
s=s.replace(old,new,1)
sess.write_text(s)
print("RUNTIME_DIAGNOSTICS_OK")
