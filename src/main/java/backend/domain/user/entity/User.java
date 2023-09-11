package astarmize.domain.user.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import astarmize.domain.user.entity.enums.AuthType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@Table(name = "USERS")
public class User {

	@Id
	@Column(name = "USER_SEQ")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long seq;

	@Column(name = "USER_ID")
	private String userId;

	@Column(name = "NAME", nullable = false)
	private String name;

	@Size(min = 8)
	@Column(name = "PASSWORD", nullable = false)
	private String password;

	// @Column(name = "COMPANY", nullable = false)
	// private String Company;

	@Enumerated(EnumType.STRING)
	private AuthType authType;
}
