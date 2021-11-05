	if domainProcessing(latest) {
		msg := "Cannot modify domain while configuration processing"
		setSyncedCondition(desired, corev1.ConditionFalse, &msg, nil)
		return desired, requeueWaitWhileProcessing
	}
