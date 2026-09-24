	if err := validateVPCEndpointAccess(desired); err != nil {
		return nil, err
	}
	input.Account, input.Service = vpcEndpointAccessPrincipal(aws.ToString(desired.ko.Spec.Principal))
