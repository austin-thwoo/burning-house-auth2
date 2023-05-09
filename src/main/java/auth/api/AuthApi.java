package auth.api;


//import io.swagger.annotations.*;


import auth.application.AuthService;
import auth.application.LoginService;
import auth.application.RegisterService;
import auth.domain.User;
import auth.dto.request.LoginCommand;
import auth.dto.request.UserRegisterCommand;
import auth.dto.response.TokenResponse;
import globalCommon.dto.response.ApiResponse;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

import org.springframework.web.bind.annotation.*;

import java.util.Date;


@RestController
@RequiredArgsConstructor
@Api(value = "미인증 사용자")
@RequestMapping("/auth")
public class AuthApi {

    private final AuthService authService;
    private final RegisterService registerService;
    private final LoginService loginService;

    @GetMapping("/api/hello")
    public String hello() {
        return "안녕하세요. 현재 서버시간은 " + new Date() + "입니다. \n";
    }


    @ApiOperation(value = "회원가입")
    @PostMapping
    public ApiResponse<TokenResponse> save(@RequestBody UserRegisterCommand registerCommand) {
        return new ApiResponse<>(registerService.register(registerCommand));
    }

    @ApiResponses(value = {
            @io.swagger.annotations.ApiResponse(code = 200, message = "로그인을 성공했습니다."),
            @io.swagger.annotations.ApiResponse(code = 404, message = "고객 아이디로 정보를 조회할 수 없습니다.\n삭제되거나 없는 고객입니다.")
    })
    @ApiOperation(value = "로그인", notes = "로그인->토큰발행")
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@RequestBody LoginCommand loginCommand) {
        return new ApiResponse<>(loginService.login(loginCommand));
    }


////////////////////////////////////////////////////////////////////////////////////
    @ApiResponses(value = {
            @io.swagger.annotations.ApiResponse(code = 200, message = "로그인을 성공했습니다."),
            @io.swagger.annotations.ApiResponse(code = 404, message = "고객 아이디로 정보를 조회할 수 없습니다.\n삭제되거나 없는 고객입니다.")
    })
    @ApiOperation(value = "로그인", notes = "로그인->토큰발행")
    @PostMapping("/check")
    public ApiResponse<String> idCheck(@AuthenticationPrincipal User principal) {
        return new ApiResponse<>(loginService.idCheck(principal));
    }

    @ApiOperation(value = "아이디 중복확인 버튼")
    @GetMapping("/overlap")
    public ApiResponse<Boolean> usernameOverLap(@RequestParam String userName) {
        return new ApiResponse<>(authService.usernameOverLap(userName));
    }
}

