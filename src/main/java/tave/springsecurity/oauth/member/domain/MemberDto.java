package tave.springsecurity.oauth.member.domain;

import lombok.Getter;

public record MemberDto(
        Long id,
        String email,
        String name,
        String socialId,
        Role role
) {
}
