package tave.springsecurity.oauth.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import tave.springsecurity.oauth.member.domain.Member;
import tave.springsecurity.oauth.member.domain.MemberDto;
import tave.springsecurity.oauth.member.domain.MemberRepository;
import tave.springsecurity.oauth.member.domain.PrincipalDetail;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return memberRepository.findByEmail(username)
                .map(this::createPrincipalDetail)
                .orElseThrow(() -> new UsernameNotFoundException("등록되지 않은 사용자입니다"));
    }

    private PrincipalDetail createPrincipalDetail(Member member) {
        return new PrincipalDetail(
                new MemberDto(
                        member.getId(),
                        member.getEmail(),
                        member.getName(),
                        member.getSocialId(),
                        member.getRole()
                ),
                Collections.singleton(new SimpleGrantedAuthority(member.getRole().getValue()))
        );
    }
}
