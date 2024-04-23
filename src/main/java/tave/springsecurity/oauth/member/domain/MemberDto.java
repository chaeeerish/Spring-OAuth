package tave.springsecurity.oauth.member.domain;

public record MemberDto(
        Long id,
        String email,
        String name,
        String socialId,
        Role role
) {
}
