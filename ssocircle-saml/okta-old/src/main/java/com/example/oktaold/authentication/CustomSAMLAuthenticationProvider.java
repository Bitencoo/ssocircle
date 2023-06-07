package com.example.oktaold.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

public class CustomSAMLAuthenticationProvider extends SAMLAuthenticationProvider {

    @Override
    public Collection<? extends GrantedAuthority> getEntitlements(SAMLCredential credential, Object userDetail)
    {
        if (userDetail instanceof UserDetails)
        {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UserDetails) userDetail).getAuthorities());
            return authorities;
        }
        else if(userDetail instanceof UsernamePasswordAuthenticationToken)
        {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UsernamePasswordAuthenticationToken) userDetail).getAuthorities());
            return authorities;

        } else {
            return Collections.emptyList();
        }
    }
}
