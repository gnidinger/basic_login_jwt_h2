package astarmize.global.config.security.userDetails;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import astarmize.domain.user.entity.User;
import lombok.Getter;

@Getter
public class AuthUser extends User implements UserDetails {

    private Long seq;
    private String userId;
    private String password;
    private List<String> roles;
    private String name;

    private AuthUser(User user) {
        this.seq = user.getSeq();
        this.userId = user.getUserId();
        this.password = user.getPassword();
        this.roles = List.of(user.getAuthType().toString());
        this.name = user.getName();
    }

    private AuthUser(Long seq, List<String> roles) {
        this.seq = seq;
        this.password = "";
        this.roles = roles;
    }

    public static AuthUser of(User user) {
        return new AuthUser(user);
    }

    public static AuthUser of(Long id, List<String> roles) {
        return new AuthUser(id, roles);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(roles.get(0)));
    }

    @Override
    public String getUsername() {
        return userId;
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
