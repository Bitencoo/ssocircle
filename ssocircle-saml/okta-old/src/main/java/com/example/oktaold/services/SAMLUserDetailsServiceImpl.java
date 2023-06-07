package com.example.oktaold.services;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    @Override
    public UserDetails loadUserBySAML(SAMLCredential credential) {
        String username = credential.getNameID().getValue();
        List<GrantedAuthority> authorities = getAuthorities(credential);
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        return new User(username, "", enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    private List<GrantedAuthority> getAuthorities(SAMLCredential credential) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // Extract desired attributes from SAML response
        List<Attribute> attributes = credential.getAttributes();
        for (Attribute attribute : attributes) {
            if ("roles".equals(attribute.getName())) {  // Assuming the attribute name for roles is "roles"
                List<XMLObject> attributeValues = attribute.getAttributeValues();
                for (XMLObject attributeValue : attributeValues) {
                    String role = attributeValue.getDOM().getTextContent();
                    authorities.add(new SimpleGrantedAuthority(role));
                }
            }
        }

        return authorities;
    }

}