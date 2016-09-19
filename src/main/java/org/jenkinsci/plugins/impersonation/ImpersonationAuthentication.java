package org.jenkinsci.plugins.impersonation;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

public class ImpersonationAuthentication extends AbstractAuthenticationToken {

    private final GrantedAuthority principal;
    private final Object credentials;

    public ImpersonationAuthentication(Authentication original, GrantedAuthority... authorities) {
        super(authorities);
        setAuthenticated(original.isAuthenticated());
        setDetails(original.getDetails());
        principal = authorities[0];
        this.credentials = original;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal.getAuthority();
    }

}
