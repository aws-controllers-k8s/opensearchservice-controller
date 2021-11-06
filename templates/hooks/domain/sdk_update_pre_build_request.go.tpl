	if domainProcessing(latest) {
		msg := "Cannot modify domain while configuration processing"
		ackcondition.SetSynced(desired, corev1.ConditionFalse, &msg, nil)
		return desired, requeueWaitWhileProcessing
	}
