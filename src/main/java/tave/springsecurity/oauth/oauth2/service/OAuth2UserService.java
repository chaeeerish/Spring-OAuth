package tave.springsecurity.oauth.oauth2.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import tave.springsecurity.oauth.member.domain.*;
import tave.springsecurity.oauth.oauth2.domain.KakaoUserInfo;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        KakaoUserInfo kakaoUserInfo = new KakaoUserInfo(attributes);
        String socialId = kakaoUserInfo.getSocialId();
        String name = kakaoUserInfo.getName();

        Optional<Member> bySocialId = memberRepository.findBySocialId(socialId);
        Member member = bySocialId.orElseGet(() -> saveSocialMember(socialId, name));
        MemberDto memberDto = new MemberDto(member.getId(), member.getEmail(), member.getName(), member.getSocialId(), member.getRole());

        return new PrincipalDetail(
                memberDto,
                Collections.singleton(new SimpleGrantedAuthority(member.getRole().getValue())),
                attributes
        );
    }

    public Member saveSocialMember(String socialId, String name) {
        Member newMember = Member.createMember(null, null, name, socialId, Role.USER);
        return memberRepository.save(newMember);
    }
}
