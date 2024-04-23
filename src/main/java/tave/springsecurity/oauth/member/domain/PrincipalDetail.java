package tave.springsecurity.oauth.member.domain;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Data
public class PrincipalDetail implements UserDetails, OAuth2User {
    private MemberDto memberDto;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public PrincipalDetail(MemberDto memberDto, Collection<? extends GrantedAuthority> authorities) {
        this.memberDto = memberDto;
        this.authorities = authorities;
    }

    public PrincipalDetail(MemberDto memberDto, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
        this.memberDto = memberDto;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    public Map<String, Object> getMemberInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("id", memberDto.id());
        info.put("email", memberDto.email());
        info.put("name", memberDto.name());
        info.put("socialId", memberDto.socialId());
        info.put("role", memberDto.role().getValue());
        return info;
    }

    @Override
    public String getName() {
        return memberDto.email();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return memberDto.name();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
