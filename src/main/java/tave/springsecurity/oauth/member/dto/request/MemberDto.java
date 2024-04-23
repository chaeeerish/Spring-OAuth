package tave.springsecurity.oauth.member.dto.request;

import lombok.Getter;

@Getter
public class MemberDto {
    private String email;
    private String password;
    private String name;
}
