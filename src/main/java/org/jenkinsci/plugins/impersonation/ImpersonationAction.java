package org.jenkinsci.plugins.impersonation;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import hudson.model.TransientUserActionFactory;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import hudson.util.HttpResponses;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * An action for {@link User} instances that permits the current user to impersonate a reduced set of permissions
 * corresponding to a group to which the user is a member of.
 */
public class ImpersonationAction implements Action, AccessControlled {

    /**
     * Exposed to jelly view to allow permission rendering.
     */
    @Restricted(NoExternalUse.class)
    @SuppressWarnings("unused")
    public static final Permission READ = Item.READ;

    /**
     * The user this action is associated with.
     */
    @NonNull
    private final User user;

    /**
     * Constructor.
     *
     * @param user the user to associate the action with.
     */
    public ImpersonationAction(@NonNull User user) {
        this.user = user;
    }

    /**
     * Gets the user this action is associated with.
     *
     * @return the user this action is associated with.
     */
    @NonNull
    public User getUser() {
        return user;
    }

    /**
     * Gets the names of the authorities that this action is associated with.
     *
     * @return the names of the authorities that this action is associated with.
     */
    @NonNull
    public List<String> getAuthorities() {
        Authentication authentication = Jenkins.getAuthentication();
        GrantedAuthority[] authorities = authentication.getAuthorities();
        if (authorities == null) {
            return Collections.emptyList();
        }
        String id = authentication.getName();
        List<String> result = new ArrayList<>(authorities.length);
        for (GrantedAuthority a : authorities) {
            String n = a.getAuthority();
            if (n != null && !User.idStrategy().equals(n, id)) {
                result.add(n);
            }
        }
        Collections.sort(result, String.CASE_INSENSITIVE_ORDER);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getIconFileName() {
        Authentication a = Jenkins.getAuthentication();
        if (a instanceof ImpersonationAuthentication) {
            return null;
        }
        GrantedAuthority[] authorities = a.getAuthorities();
        return authorities != null && authorities.length > 0 && User.idStrategy().equals(a.getName(), user.getId())
                ? "plugin/impersonation/images/24x24/impersonate.png"
                : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getDisplayName() {
        return Messages.ImpersonationAction_DisplayName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getUrlName() {
        return "impersonate";
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public ACL getACL() {
        return new ACL() {
            /**
             * {@inheritDoc}
             */
            @Override
            public boolean hasPermission(@Nonnull Authentication a, @Nonnull Permission permission) {
                return User.idStrategy().equals(a.getName(), user.getId());
            }
        };
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void checkPermission(@Nonnull Permission permission) throws AccessDeniedException {
        getACL().checkPermission(permission);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasPermission(@Nonnull Permission permission) {
        return getACL().hasPermission(permission);
    }

    @RequirePOST
    public HttpResponse doImpersonate(StaplerRequest req, @QueryParameter String name) {
        Authentication auth = Jenkins.getAuthentication();
        GrantedAuthority[] authorities = auth.getAuthorities();
        if (authorities == null || StringUtils.isBlank(name)) {
            return HttpResponses.redirectToContextRoot();
        }
        GrantedAuthority authority = null;
        for (GrantedAuthority a : authorities) {
            if (a.getAuthority().equals(name)) {
                authority = a;
                break;
            }
        }
        if (authority == null) {
            return HttpResponses.redirectToContextRoot();
        }
        if (!SecurityRealm.AUTHENTICATED_AUTHORITY.equals(authority)) {
            ACL.impersonate(new ImpersonationAuthentication(auth, authority, SecurityRealm.AUTHENTICATED_AUTHORITY));
        } else {
            ACL.impersonate(new ImpersonationAuthentication(auth, SecurityRealm.AUTHENTICATED_AUTHORITY));
        }
        return HttpResponses.redirectToContextRoot();
    }

    public String impersonationUrl(String authority) throws UnsupportedEncodingException {
        return String.format("impersonate?name=%s", URLEncoder.encode(authority, "UTF-8"));

    }

    /**
     * Registers the action for all users (only displays on the current user if the current user is a member of at least
     * one group.
     */
    @Extension
    public static class Factory extends TransientUserActionFactory {

        /**
         * {@inheritDoc}
         */
        @Override
        public Collection<? extends Action> createFor(User target) {
            return Collections.singletonList(new ImpersonationAction(target));
        }
    }
}
