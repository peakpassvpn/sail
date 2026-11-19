//! Finite observation categories on the existing semaphore/Place ownership.
use super::*;
use crate::session::Network;

struct Quiet;

#[async_trait]
impl OutboundDatagramRecvHalf for Quiet {
    async fn recv_from(&mut self, _: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        std::future::pending().await
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for Quiet {
    async fn send_to(&mut self, data: &[u8], _: &SocksAddr) -> io::Result<usize> {
        Ok(data.len())
    }
    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OutboundDatagram for Quiet {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(Quiet), Box::new(Quiet))
    }
}

#[tokio::test]
async fn permit_classes_follow_tcp_unknown_and_both_udp_held_halves() {
    let sessions = Sessions::new(3).unwrap();
    let tcp = sessions
        .enter_network(Duration::ZERO, Network::Tcp)
        .await
        .unwrap();
    let udp = sessions
        .enter_network(Duration::ZERO, Network::Udp)
        .await
        .unwrap();
    let unknown = sessions.enter(Duration::ZERO).await.unwrap();
    let snapshot = sessions.diagnostics_snapshot();
    assert_eq!(snapshot.admitted_total, Some(3));
    let classes = snapshot.permit_classes.unwrap();
    for class in [&classes.tcp, &classes.udp, &classes.unknown] {
        assert_eq!(class.granted_total, 1);
        assert_eq!(class.dropped_total, 0);
        assert_eq!(class.live, 1);
    }
    let (recv, send) = Held::wrap(Box::new(Quiet), udp).split();
    drop(recv);
    let classes = sessions.diagnostics_snapshot().permit_classes.unwrap();
    assert_eq!(
        classes.udp.live, 1,
        "one Held half still owns the same Place"
    );
    assert_eq!(classes.udp.dropped_total, 0);
    drop(tcp);
    drop(unknown);
    drop(send);
    assert_eq!(sessions.live(), 0);
    let classes = sessions.diagnostics_snapshot().permit_classes.unwrap();
    for class in [&classes.tcp, &classes.udp, &classes.unknown] {
        assert_eq!(class.granted_total, 1);
        assert_eq!(class.dropped_total, 1);
        assert_eq!(class.live, 0);
    }
}

#[tokio::test]
async fn permit_classes_do_not_grant_on_timeout_or_cancelled_waits() {
    let sessions = Sessions::new(1).unwrap();
    let tcp = sessions
        .enter_network(Duration::ZERO, Network::Tcp)
        .await
        .unwrap();
    let mut queued = Box::pin(sessions.enter_network(Duration::from_secs(1), Network::Udp));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    drop(queued);
    assert!(sessions
        .enter_network(Duration::from_millis(1), Network::Udp)
        .await
        .is_none());
    let mut woken = Box::pin(sessions.enter_network(Duration::from_secs(1), Network::Udp));
    assert!(futures::poll!(woken.as_mut()).is_pending());
    drop(tcp);
    drop(woken); // Semaphore wake is not a returned Place/grant.
    assert_eq!(sessions.live(), 0);
    let snapshot = sessions.diagnostics_snapshot();
    assert_eq!(snapshot.admitted_total, Some(1));
    assert_eq!(snapshot.wait_timeout_total, Some(1));
    assert_eq!(snapshot.wait_cancelled_total, Some(2));
    assert_eq!(snapshot.waiting, Some(0));
    let classes = snapshot.permit_classes.unwrap();
    assert_eq!(classes.udp, diagnostics::PermitCounts::default());
    assert_eq!(classes.unknown, diagnostics::PermitCounts::default());
    assert_eq!(classes.tcp.granted_total, 1);
    assert_eq!(classes.tcp.dropped_total, 1);
    let udp = sessions
        .enter_network(Duration::ZERO, Network::Udp)
        .await
        .unwrap();
    drop(udp);
    let classes = sessions.diagnostics_snapshot().permit_classes.unwrap();
    assert_eq!(classes.udp.granted_total, 1);
    assert_eq!(classes.udp.dropped_total, 1);
    assert_eq!(classes.udp.live, 0);
}

#[tokio::test]
async fn permit_observer_storage_drops_without_crossing_pool_epochs() {
    let old = Sessions::new(1).unwrap();
    let held = old
        .enter_network(Duration::ZERO, Network::Udp)
        .await
        .unwrap();
    let old_storage = Arc::downgrade(&old.diagnostics);
    drop(old);
    assert!(old_storage.upgrade().is_some());
    let current = Sessions::new(1).unwrap();
    let before = current.diagnostics_snapshot();
    drop(held);
    assert!(
        old_storage.upgrade().is_none(),
        "observer storage must not leak"
    );
    assert_eq!(current.diagnostics_snapshot(), before);
    let current_place = current
        .enter_network(Duration::ZERO, Network::Udp)
        .await
        .unwrap();
    drop(current_place);
    let classes = current.diagnostics_snapshot().permit_classes.unwrap();
    assert_eq!(classes.udp.granted_total, 1);
    assert_eq!(classes.udp.dropped_total, 1);
}

#[test]
fn permit_class_absence_stays_unknown_and_existing_json_fields_remain() {
    let absent = serde_json::to_value(diagnostics::AdmissionDiagnostics::default()).unwrap();
    assert!(absent["permit_classes"].is_null());
    assert!(absent["live"].is_null());
    assert!(absent["active_cancel_total"].is_null());
    let sessions = Sessions::new(128).unwrap();
    let present = serde_json::to_value(sessions.diagnostics_snapshot()).unwrap();
    assert_eq!(present["limit"], 128);
    assert_eq!(present["live"], 0);
    assert_eq!(present["permit_classes"]["tcp"]["live"], 0);
    assert_eq!(present["permit_classes"]["udp"]["granted_total"], 0);
    assert_eq!(present["permit_classes"]["unknown"]["dropped_total"], 0);
}

#[tokio::test]
async fn permit_classes_task_cancellation_releases_one_observed_place() {
    let sessions = Arc::new(Sessions::new(1).unwrap());
    let owner = sessions.clone();
    let (ready, admitted) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _held = owner
            .enter_network(Duration::ZERO, Network::Udp)
            .await
            .unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    admitted.await.unwrap();
    assert_eq!(sessions.live(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(sessions.live(), 0);
    let classes = sessions.diagnostics_snapshot().permit_classes.unwrap();
    assert_eq!(classes.udp.granted_total, 1);
    assert_eq!(classes.udp.dropped_total, 1);
    assert_eq!(classes.udp.live, 0);
    let next = sessions
        .enter_network(Duration::ZERO, Network::Tcp)
        .await
        .unwrap();
    drop(next);
    let classes = sessions.diagnostics_snapshot().permit_classes.unwrap();
    assert_eq!(classes.tcp.granted_total, 1);
    assert_eq!(classes.tcp.dropped_total, 1);
}
