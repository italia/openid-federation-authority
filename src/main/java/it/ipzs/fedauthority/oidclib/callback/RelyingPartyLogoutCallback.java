package it.ipzs.fedauthority.oidclib.callback;

import it.ipzs.fedauthority.oidclib.model.AuthnRequest;
import it.ipzs.fedauthority.oidclib.model.AuthnToken;

public interface RelyingPartyLogoutCallback {

	public void logout(String userKey, AuthnRequest authnRequest, AuthnToken authnToken);

}
