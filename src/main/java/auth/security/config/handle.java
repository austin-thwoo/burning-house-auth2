package auth.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
public class handle extends HandlerInterceptorAdapter {


    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           @Nullable ModelAndView modelAndView) throws Exception {
//            HttpSession httpSession = request.getSession();
//            ApiResponse<HttpServletResponse> apiResponse=new ApiResponse<>(response);
//            return Optional.ofNullable(httpSession.getAttribute("USER")).isPresent();
        log.info("아빠사자");

    }

}


