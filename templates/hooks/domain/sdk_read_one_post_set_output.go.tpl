	if resp.DomainStatus.AutoTuneOptions != nil {
		if ready, err := isAutoTuneOptionReady(resp.DomainStatus.AutoTuneOptions); err != nil {
			return latest, ackrequeue.Needed(err)
		} else if !ready {
			return latest, ackrequeue.Needed(fmt.Errorf("waiting for AutotuneOptions to sync. Current state: ", resp.DomainStatus.AutoTuneOptions.State))
		}
		ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(resp.DomainStatus.AutoTuneOptions.State))
	}

	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
	} else {
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionTrue, nil, nil)
	}

