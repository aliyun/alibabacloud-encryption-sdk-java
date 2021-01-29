/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyun.encryptionsdk.examples.rds;

import com.aliyun.encryptionsdk.exception.AliyunException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@RunWith(SpringRunner.class)
@SpringBootTest
public class EncryptionTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionTest.class);
    private static final String NAME = "Test";
    private static final String EMAIL = "test@example.com";

    private long id;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private UserRepository userRepository;

    @Before
    public void setUp() {
        User user = new User();
        user.setName(NAME);
        user.setEmail(EMAIL);
        id = userRepository.save(user).getId();
    }

    @Test
    public void readEncrypted() {
        User user = jdbcTemplate.queryForObject(
                "select * from user where id = ?",
                (resultSet, i) -> {
                    User result = new User();
                    result.setId(resultSet.getLong("id"));
                    result.setName(resultSet.getString("name"));
                    result.setEmail(resultSet.getString("email"));
                    return result;
                },
                id
        );

        assertNotEquals(user.getName(), NAME);
        LOGGER.info("======Encrypted name value in DB is {}", user.getName());
        assertEquals(user.getEmail(), EMAIL);
        LOGGER.info("======Encrypted email value in DB is {}", user.getEmail());
    }

    @Test
    public void readDecrypted() {
        User user = userRepository.findById(id).orElseThrow(AliyunException::new);
        assertEquals(user.getName(), NAME);
        assertEquals(user.getEmail(), EMAIL);
        LOGGER.info("======Decrypted name value is {}", user.getName());
        LOGGER.info("======Decrypted email value is {}", user.getEmail());
    }

}
