	for {
		token := aws.ToString(resp.NextToken)
		if token == "" || token == aws.ToString(input.NextToken) {
			break
		}
		input.NextToken = resp.NextToken
		var page *svcsdk.ListVpcEndpointAccessOutput
		page, err = rm.sdkapi.ListVpcEndpointAccess(ctx, input)
		rm.metrics.RecordAPICall("READ_MANY", "ListVpcEndpointAccess", err)
		if err != nil {
			var awsErr smithy.APIError
			if errors.As(err, &awsErr) && awsErr.ErrorCode() == "ResourceNotFoundException" {
				return nil, ackerr.NotFound
			}
			return nil, err
		}
		page.AuthorizedPrincipalList = append(resp.AuthorizedPrincipalList, page.AuthorizedPrincipalList...)
		resp = page
	}
