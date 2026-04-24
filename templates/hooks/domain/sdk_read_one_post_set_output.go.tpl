	// To prevent https://github.com/aws-controllers-k8s/community/issues/2431
	if r.ko.Spec.VPCOptions != nil {
		if ko.Spec.VPCOptions == nil {
			ko.Spec.VPCOptions = &svcapitypes.VPCOptions{}
		}
		ko.Spec.VPCOptions.SecurityGroupRefs = r.ko.Spec.VPCOptions.SecurityGroupRefs
		ko.Spec.VPCOptions.SubnetRefs = r.ko.Spec.VPCOptions.SubnetRefs
	}

	ko.Spec.Tags, err = getTags(ctx, string(*ko.Status.ACKResourceMetadata.ARN), rm.sdkapi, rm.metrics)
	if err != nil {
		return &resource{ko}, err
	}

  err = rm.setAutoTuneOptions(ctx, ko)
	if err != nil {
		return &resource{ko}, err
	}
	checkDomainStatus(resp, ko)
