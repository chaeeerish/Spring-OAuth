package tave.springsecurity.oauth.member.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tave.springsecurity.oauth.member.domain.Member;
import tave.springsecurity.oauth.member.domain.PrincipalDetail;
import tave.springsecurity.oauth.member.dto.request.MemberDto;
import tave.springsecurity.oauth.member.service.MemberService;

import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/signUp")
    public Map<String, String> signUp(@RequestBody MemberDto memberDTO) {
        Map<String, String> response = new HashMap<>();
        Optional<Member> byEmail = memberService.findByEmail(memberDTO.getEmail());
        if (byEmail.isPresent()) {
            response.put("error", "이미 존재하는 이메일입니다");
        } else {
            memberService.saveMember(memberDTO);
            response.put("success", "성공적으로 처리하였습니다");
        }
        return response;
    }

    @GetMapping("/member/info")
    public ResponseEntity<Member> getMember(@AuthenticationPrincipal PrincipalDetail principalDetail) {
        Long memberId = principalDetail.getMemberDto().id();
        Member member = memberService.findById(memberId)
                .orElseThrow(() -> new NoSuchElementException("Member not found"));
        return ResponseEntity.ok(member);
    }
}
