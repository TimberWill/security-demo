package com.whl.cloud;

import com.baomidou.mybatisplus.core.toolkit.Assert;
import com.jayway.jsonpath.internal.function.text.Length;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.lang.invoke.VarHandle;
import java.util.*;

public class Test {

  @org.junit.jupiter.api.Test
  void testPassword() {
    PasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String encode = encoder.encode("123456");
    System.out.println(encode);

    //密码校验
    Assert.isTrue(encoder.matches("123456", encode), "密码校验失败");
  }

  @org.junit.jupiter.api.Test
  void test01() {
    int[] nums = new int[]{0,3,7,2,5,8,4,6,0,1};
    System.out.println(longestConsecutive2(nums));
  }

  public int longestConsecutive(int[] nums) {
    ArrayList<Integer> lens = new ArrayList<>();
    Arrays.sort(nums);

    if (nums.length == 1) {
      return 1;
    }

    for (int i = 0; i < nums.length; i++) {
      int count = 1;
      for (int j = i+1; j < nums.length; j++) {
        if (nums[j-1] + 1 == nums[j]) {
          count ++;
        } else if (nums[j] == nums[j-1]) {
          if (j == nums.length-1) {
            lens.add(count);
          }
          continue;
        } else {
          lens.add(count);
          break;
        }
        if (j == nums.length-1) {
          lens.add(count);
        }
      }
    }
    Collections.sort(lens);

    return lens.isEmpty() ? 0:lens.get(lens.size()-1);
  }

  public int longestConsecutive2(int[] nums) {
    if (nums == null || nums.length == 0) {
      return 0;
    }
    Set<Integer> numSet = new HashSet<>();
    for (int num : nums) {
      numSet.add(num);
    }

    int len = 0;
    for (Integer num : numSet) {
      if (!numSet.contains(num-1)) {
        //可以确定为起点
        int currentNum = num;
        int currentLen = 1;
        while (numSet.contains(currentNum + 1)) {
          currentLen ++;
          currentNum ++;
        }
        len =  Math.max(len, currentLen);
      }
    }
    return len;
  }

  @org.junit.jupiter.api.Test
  void test02() {
    String[] strings = {"eat", "tea", "tan", "ate", "nat", "bat"};
    List<List<String>> lists = groupAnagrams2(strings);
    System.out.println(lists);
  }

  /**
   * 无法处理多个相同字符的情况，对空字符也处理不了.
   */
  public List<List<String>> groupAnagrams(String[] strs) {
    Set<Set<Character>> sets = new HashSet<>();
    for (String str : strs) {
      char[] charArray = str.toCharArray();
      Set<Character> set = new HashSet<>();
      for (char c : charArray) {
        set.add(c);
      }
      sets.add(set);
    }
    List<List<String>> lists = new ArrayList<>();
    for (Set<Character> set : sets) {
      List<String> list = new ArrayList<>();
      for (String str : strs) {
        char[] charArray = str.toCharArray();
        int count = 0;
        for (char c : charArray) {
          if (set.contains(c)) {
            count ++;
          }
        }
        if (count == set.size()) {
          list.add(str);
        }
      }

      lists.add(list);
    }
    return lists;
  }

  /**
   * 问题：HashSet 使用 equals() 和 hashCode() 来判断元素是否相等。
   *
   * 数组的 equals() 方法：比较的是引用地址，而不是数组内容
   *
   * 数组的 hashCode()：基于对象地址，不是基于内容
   *
   * 结果：即使两个数组内容完全相同，HashSet 也会认为是不同元素！
   * @param strs
   * @return
   */
  public List<List<String>> groupAnagrams2(String[] strs) {
    HashSet<int[]> sets = new HashSet<>();
    for (String str : strs) {
      int[] ints = new int[26];
      char[] charArray = str.toCharArray();
      for (char c : charArray) {
        int ascii = c - 'a';
        ints[ascii] += 1;
      }
      sets.add(ints);
    }
    List<List<String>> lists = new ArrayList<>();
    for (int[] set : sets) {
      List<String> list = new ArrayList<>();
      for (String str : strs) {
        int[] ints = new int[26];
        char[] charArray = str.toCharArray();
        for (char c : charArray) {
          int ascii = c - 'a';
          ints[ascii] += 1;
        }
        if (Arrays.equals(set, ints)) {
          list.add(str);
        }
      }

      lists.add(list);
    }
    return lists;
  }

  /**
   * HashMap + List/Set可以处理一对多关系.
   * Map<String, List<String>>
   *
   * @param strs
   * @return
   */
  public List<List<String>> groupAnagrams3(String[] strs) {

    Map<String, List<String>> map = new HashMap<>();
    for (String str : strs) {
      char[] charArray = str.toCharArray();
      Arrays.sort(charArray);
      //如果key不存在就创建新List，然后添加元素
      map.computeIfAbsent(String.valueOf(charArray), k -> new ArrayList<>()).add(str);
    }

    Collection<List<String>> values = map.values();
    return new ArrayList<>(values);
  }

  @org.junit.jupiter.api.Test
  void test03() {
    String s = "dvfv";
    System.out.println(lengthOfLongestSubstring3(s));
  }

  public static int lengthOfLongestSubstring(String s) {
    if (s == null || s.isEmpty()) {
      return 0;
    }
    char[] charArray = s.toCharArray();
    Set<Character> characters = new HashSet<>();
    ArrayList<Integer> integers = new ArrayList<>();

    for (int i = 0; i < charArray.length; i++) {
      if (!characters.contains(charArray[i])) {
        characters.add(charArray[i]);
      } else {
        integers.add(characters.size());
        characters.clear();
      }
    }
    integers.add(characters.size());
    Collections.sort(integers);
    return integers.get(integers.size()-1);
  }

  public static int lengthOfLongestSubstring2(String s) {
    if (s == null || s.isEmpty()) {
      return 0;
    }
    char[] charArray = s.toCharArray();
    int maxLen = 1;

    for (int i = 0; i < charArray.length; i++) {
      Set<Character> characters = new HashSet<>();
      characters.add(charArray[i]);
      for (int j = i+1; j < charArray.length; j++) {
        if (!characters.contains(charArray[j])) {
          characters.add(charArray[j]);
          maxLen = Math.max(maxLen, characters.size());
        } else {
          break;
        }
      }
    }
    return maxLen;
  }

  public static int lengthOfLongestSubstring3(String s) {
    if (s == null || s.isEmpty()) {
      return 0;
    }
    int left = 0;
    int maxLen = 1;
    Set<Character> set = new HashSet<>();
    set.add(s.charAt(left));
    for (int right = 1; right < s.length(); right++) {
      char c = s.charAt(right);
      while (set.contains(c)) {
        //可能需要好几次才能移除掉
        set.remove(s.charAt(left));
        left++;
      }
      set.add(c);
      maxLen = Math.max(maxLen, set.size());
    }
    return maxLen;
  }



}
