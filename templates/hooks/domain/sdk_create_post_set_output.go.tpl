	// To prevent https://github.com/aws-controllers-k8s/community/issues/2431
	if desired.ko.Spec.VPCOptions != nil {
		if ko.Spec.VPCOptions == nil {
			ko.Spec.VPCOptions = &svcapitypes.VPCOptions{}
		}
		ko.Spec.VPCOptions.SecurityGroupRefs = desired.ko.Spec.VPCOptions.SecurityGroupRefs
		ko.Spec.VPCOptions.SubnetRefs = desired.ko.Spec.VPCOptions.SubnetRefs
	}

	err = rm.setAutoTuneOptions(ctx, ko)
	if err != nil {
		return &resource{ko}, err
	}
	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
		return &resource{ko}, nil
	}
