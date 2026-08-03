program build_rank_test
  use, intrinsic :: iso_c_binding, only: c_bool, c_double, c_int
  use, intrinsic :: ieee_arithmetic, only: ieee_value, ieee_quiet_nan
  use arach_build_rank_module, only: arach_build_rank, arach_corpus_rank
  implicit none
  real(c_double) :: untrusted
  real(c_double) :: leaf
  real(c_double) :: critical
  real(c_double) :: static_heavy
  real(c_double) :: worker_heavy
  real(c_double) :: blocked
  real(c_double) :: empty
  real(c_double) :: invalid
  real(c_double) :: not_a_number
  real(c_double) :: untrusted_corpus
  real(c_double) :: invalid_memory

  untrusted = arach_build_rank(1.0_c_double, 20_c_int, .true._c_bool, &
                               1.0_c_double, .false._c_bool)
  leaf = arach_build_rank(0.2_c_double, 0_c_int, .false._c_bool, &
                          2.0_c_double, .true._c_bool)
  critical = arach_build_rank(1.0_c_double, 5_c_int, .true._c_bool, &
                              2.0_c_double, .true._c_bool)

  if (abs(untrusted + 1.0_c_double) > epsilon(untrusted)) error stop 1
  if (critical <= leaf) error stop 2

  static_heavy = arach_corpus_rank(100_c_int, 10_c_int, 0_c_int, &
                                   200_c_int, 50_c_int, 1.0_c_double, &
                                   .true._c_bool)
  worker_heavy = arach_corpus_rank(10_c_int, 100_c_int, 0_c_int, &
                                   200_c_int, 50_c_int, 1.0_c_double, &
                                   .true._c_bool)
  blocked = arach_corpus_rank(100_c_int, 10_c_int, 100_c_int, &
                              200_c_int, 50_c_int, 1.0_c_double, &
                              .true._c_bool)
  empty = arach_corpus_rank(0_c_int, 0_c_int, 0_c_int, &
                            0_c_int, 0_c_int, 0.0_c_double, &
                            .true._c_bool)
  invalid = arach_corpus_rank(-1_c_int, 0_c_int, 0_c_int, &
                              0_c_int, 0_c_int, 0.0_c_double, &
                              .true._c_bool)
  not_a_number = ieee_value(0.0_c_double, ieee_quiet_nan)
  untrusted_corpus = arach_corpus_rank(1_c_int, 0_c_int, 0_c_int, &
                                       0_c_int, 0_c_int, 1.0_c_double, &
                                       .false._c_bool)
  invalid_memory = arach_corpus_rank(1_c_int, 0_c_int, 0_c_int, &
                                     0_c_int, 0_c_int, not_a_number, &
                                     .true._c_bool)

  if (static_heavy <= worker_heavy) error stop 3
  if (blocked >= static_heavy) error stop 4
  if (abs(empty) > epsilon(empty)) error stop 5
  if (abs(invalid + 1.0_c_double) > epsilon(invalid)) error stop 6
  if (abs(untrusted_corpus + 1.0_c_double) > &
      epsilon(untrusted_corpus)) error stop 7
  if (abs(invalid_memory + 1.0_c_double) > &
      epsilon(invalid_memory)) error stop 8
end program build_rank_test
